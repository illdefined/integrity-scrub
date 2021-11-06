#![feature(allocator_api, int_roundings)]

use std::cell::UnsafeCell;
use std::io::{Error, Result};
use std::os::unix::fs::{FileExt, FileTypeExt};
use std::os::unix::io::AsRawFd;
use std::time::{Duration, Instant};
use std::vec::Vec;

use clap::Parser;
use libc::{c_ushort, c_int, size_t};
use nix::fcntl::{posix_fadvise, PosixFadviseAdvice};
use nix::{ioctl_read, ioctl_read_bad, ioctl_write_ptr, request_code_none};
use sensitive::alloc::Sensitive;

#[derive(Parser)]
#[clap(version = clap::crate_version!(), about = clap::crate_description!())]
struct Opt {
	/// Device path
	#[clap(parse(from_os_str), value_hint = clap::ValueHint::FilePath)]
	device: std::path::PathBuf,

	/// Do not overwrite corrupt sectors
	#[clap(short('n'), long)]
	dry_run: bool
}

struct Device {
	file: std::fs::File,
	sectors: u64,
	sector_size: usize,
	maximum_io: u16,
	null: Vec<u8>,
	buffer: UnsafeCell<Vec<u8, Sensitive>>
}

struct Chunk<'t> {
	device: &'t Device,
	index: u64,
	count: u16,
	valid: bool,
}

struct ChunkIterator<'t> {
	device: &'t Device,
	index: Option<u64>,
}

struct Sector<'t> {
	chunk: &'t Chunk<'t>,
	index: u16,
	valid: bool
}

struct SectorIterator<'t> {
	chunk: &'t Chunk<'t>,
	index: Option<u16>
}

struct Progress {
	total: u64,
	error: u64,
	start: Instant,
	last: Option<Instant>
}

ioctl_read_bad!(blksectget, request_code_none!(0x12, 103), c_ushort);
ioctl_read_bad!(blksszget, request_code_none!(0x12, 104), c_int);
ioctl_write_ptr!(blkbszset, 0x12, 113, size_t);
ioctl_read!(blkgetsize64, 0x12, 114, u64);

impl Device {
	fn open<P: AsRef<std::path::Path>>(path: P, writable: bool) -> Result<Self> {
		let file = std::fs::OpenOptions::new()
			.read(true)
			.write(writable)
			.open(path)?;

		if !file.metadata()?.file_type().is_block_device() {
			use std::io::ErrorKind;
			return Err(Error::new(ErrorKind::InvalidInput, "File is not a block device"));
		}

		let size = {
			let mut size = u64::MAX;
			unsafe { blkgetsize64(file.as_raw_fd(), &mut size) }?;
			size as u64
		};

		let sector_size = {
			let mut ssz = -1;
			unsafe { blksszget(file.as_raw_fd(), &mut ssz) }?;
			assert!(ssz > 0);
			ssz as usize
		};

		// Assert that device size is a multiple of the logical sector size
		assert!(size % sector_size as u64 == 0);

		unsafe { blkbszset(file.as_raw_fd(), &sector_size) }?;

		let maximum_io = {
			let mut sect = c_ushort::MAX;
			unsafe { blksectget(file.as_raw_fd(), &mut sect) }?;
			assert!(sect > 0);
			sect as u16
		};

		let mut buffer = Vec::with_capacity_in(maximum_io as usize * sector_size, Sensitive);

		// The allocator ensures that the memory is zero‐initialised
		unsafe { buffer.set_len(maximum_io as usize * sector_size); }

		for advice in [
			PosixFadviseAdvice::POSIX_FADV_SEQUENTIAL,
			PosixFadviseAdvice::POSIX_FADV_WILLNEED] {
			posix_fadvise(file.as_raw_fd(), 0, 0, advice)?;
		}

		Ok(Self {
			file,
			sectors: size / sector_size as u64,
			sector_size,
			maximum_io,
			null: vec![0; sector_size],
			buffer: UnsafeCell::new(buffer)
		})
	}

	fn test(&self, offset: u64, count: u16) -> Result<Option<u16>> {
		assert!(count <= self.maximum_io);

		// The contents of this buffer are never examined
		let buffer = unsafe { &mut *self.buffer.get() };

		match self.file.read_at(&mut buffer[..count as usize * self.sector_size], offset * self.sector_size as u64) {
			Ok(len) => {
				// Assert that we read a multiple of the sector size
				assert!(len % self.sector_size == 0);

				Ok(Some((len / self.sector_size) as u16))
			}

			Err(err) => {
				if let Some(libc::EIO) = err.raw_os_error() {
					Ok(None)
				} else {
					Err(err)
				}
			}
		}
	}

	fn zero(&self, offset: u64) -> Result<()> {
		let len = self.file.write_at(&self.null, offset * self.sector_size as u64)?;
		assert!(len == self.sector_size);
		Ok(())
	}

	fn flush(&self, offset: u64, count: u16) -> Result<()> {
		use libc::{sync_file_range, off64_t, SYNC_FILE_RANGE_WRITE};

		if unsafe { sync_file_range(self.file.as_raw_fd(), (offset * self.sector_size as u64) as off64_t,
			(count as usize * self.sector_size) as off64_t, SYNC_FILE_RANGE_WRITE) } != 0 {
			Err(Error::last_os_error())
		} else {
			Ok(())
		}
	}

	fn sync(&self) -> Result<()> {
		self.file.sync_data()
	}

	fn acquire(&self, offset: u64, count: u16) -> Result<()> {
		use libc::off_t;

		posix_fadvise(self.file.as_raw_fd(), (offset * self.sector_size as u64) as off_t,
		              (count as usize * self.sector_size) as off_t, PosixFadviseAdvice::POSIX_FADV_WILLNEED)?;

		Ok(())
	}

	fn release(&self, offset: u64, count: u16) -> Result<()> {
		use libc::off_t;

		posix_fadvise(self.file.as_raw_fd(), (offset * self.sector_size as u64) as off_t,
		              (count as usize * self.sector_size) as off_t, PosixFadviseAdvice::POSIX_FADV_DONTNEED)?;

		Ok(())
	}

	fn chunks(&self) -> u64 {
		self.sectors.unstable_div_ceil(self.maximum_io as u64)
	}

	fn iter(&self) -> ChunkIterator {
		ChunkIterator {
			device: self,
			index: None
		}
	}
}

impl Chunk<'_> {
	fn iter(&self) -> SectorIterator {
		self.device.acquire(self.index, self.count).unwrap();
		SectorIterator {
			chunk: self,
			index: None
		}
	}

	fn flush(&self) -> Result<()> {
		self.device.flush(self.index, self.count)
	}
}

impl Drop for Chunk<'_> {
	fn drop(&mut self) {
		self.device.release(self.index, self.count).unwrap()
	}
}

impl<'t> Iterator for ChunkIterator<'t> {
	type Item = Result<Chunk<'t>>;

	fn next(&mut self) -> Option<Self::Item> {
		match self.device.test(self.index.unwrap_or(0), self.device.maximum_io) {
			Ok(Some(0)) => None,
			Ok(Some(len)) => {
				let chunk = Chunk {
					device: self.device,
					index: self.index.unwrap_or(0),
					count: len,
					valid: true
				};

				self.index = Some(self.index.unwrap_or(0) + len as u64);

				Some(Ok(chunk))
			},
			Ok(None) => {
				let chunk = Chunk {
					device: self.device,
					index: self.index.unwrap_or(0),
					count: self.device.maximum_io,
					valid: false
				};

				self.index = Some(self.index.unwrap_or(0) + self.device.maximum_io as u64);

				Some(Ok(chunk))
			},
			Err(err) => Some(Err(err))
		}
	}

	fn size_hint(&self) -> (usize, Option<usize>) {
		let rem = self.device.chunks().saturating_sub(self.index.unwrap_or(0))
		          .unstable_div_ceil(self.device.maximum_io as u64);
		(rem as usize, rem.try_into().ok())
	}
}

impl Sector<'_> {
	fn absolute(&self) -> u64 {
		self.chunk.index + self.index as u64
	}

	fn zero(&self) -> Result<()> {
		self.chunk.device.zero(self.absolute())
	}
}

impl SectorIterator<'_> {
	fn absolute(&self) -> u64 {
		self.chunk.index + self.index.unwrap_or(0) as u64
	}
}

impl<'t> Iterator for SectorIterator<'t> {
	type Item = Result<Sector<'t>>;

	fn next(&mut self) -> Option<Self::Item> {
		if let Some(index) = self.index {
			if index >= self.chunk.count {
				return None;
			}
		}

		match self.chunk.device.test(self.absolute(), 1) {
			Ok(Some(0)) => None,
			Ok(Some(len)) => {
				assert_eq!(len, 1);
				let sector = Sector {
					chunk: self.chunk,
					index: self.index.unwrap_or(0),
					valid: true
				};

				self.index = Some(self.index.unwrap_or(0) + len);

				Some(Ok(sector))
			},
			Ok(None) => {
				let sector = Sector {
					chunk: self.chunk,
					index: self.index.unwrap_or(0),
					valid: false
				};

				self.index = Some(self.index.unwrap_or(0) + 1);

				Some(Ok(sector))
			},
			Err(err) => Some(Err(err))
		}
	}

	fn size_hint(&self) -> (usize, Option<usize>) {
		let rem = std::cmp::min(
			self.chunk.count.saturating_sub(self.index.unwrap_or(0)) as u64,
			self.chunk.device.sectors.saturating_sub(self.absolute())
		);
		(rem as usize, rem.try_into().ok())
	}
}

impl Progress {
	fn new() -> Self {
		Self {
			total: 0,
			error: 0,
			start: Instant::now(),
			last: None
		}
	}

	fn rate(size: u64, duration: Duration) -> String {
		bytesize::to_string((size as u128 * 1000 / duration.as_millis().max(1)) as u64, true)
	}

	fn print(&mut self, dev: &Device, now: Instant) {
		eprintln!("\x1bM\x1b[K{:>3} %   {:>9} / {}   {:>9} / s   {} corrupt sectors",
		          self.total * 100 / dev.sectors,
		          bytesize::to_string(self.total * dev.sector_size as u64, true),
		          bytesize::to_string(dev.sectors * dev.sector_size as u64, true),
		          Self::rate(self.total * dev.sector_size as u64, now.duration_since(self.start)),
		          self.error);
		self.last = Some(now);
	}

	fn print_now(&mut self, dev: &Device) {
		self.print(dev, Instant::now());
	}

	fn print_50(&mut self, dev: &Device) {
		let now = Instant::now();

		if let Some(last) = self.last {
			if now.duration_since(last) >= Duration::from_millis(50) {
				self.print(dev, now);
			}
		} else if self.last.is_none() {
			self.print(dev, now);
		}
	}
}

fn main() -> Result<()> {
	let opt = Opt::parse();
	let dev = Device::open(&opt.device, !opt.dry_run)?;

	let mut prog = Progress::new();

	eprintln!();
	prog.print_now(&dev);

	for chunk in dev.iter() {
		let chunk = chunk?;

		prog.print_50(&dev);

		if !chunk.valid {
			for sector in chunk.iter() {
				let sector = sector?;

				if !sector.valid {
					prog.error += 1;

					if !opt.dry_run {
						sector.zero()?;
					}
				}
			}

			chunk.flush()?;
		}

		prog.total += chunk.count as u64;
	}

	prog.print_now(&dev);
	dev.sync()
}
