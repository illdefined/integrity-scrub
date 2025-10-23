#![feature(allocator_api)]

use std::cell::UnsafeCell;
use std::io::{Error, Result, IsTerminal, stderr};
use std::os::unix::fs::{FileExt, FileTypeExt, OpenOptionsExt};
use std::os::unix::io::AsRawFd;
use std::time::{Duration, Instant};

use clap::Parser;
use bytesize::ByteSize;
use libc::{c_ushort, c_int, size_t};
use nix::{ioctl_read, ioctl_read_bad, ioctl_write_ptr, request_code_none};
use sensitive::alloc::Sensitive;

#[derive(Parser)]
#[command(version, about)]
#[allow(clippy::struct_excessive_bools)]
struct Opt {
	/// Device path
	device: std::path::PathBuf,

	/// Set idle I/O scheduling class
	#[arg(short, long)]
	idle: bool,

	/// Do not overwrite corrupt sectors
	#[arg(short('n'), long)]
	dry_run: bool,

	/// Force operation even if device is busy
	#[arg(short, long)]
	force: bool,

	/// Disable progress reporting
	#[arg(short, long)]
	quiet: bool,

	/// Enumerate corrupt sectors to standard output
	#[arg(short, long)]
	enumerate: bool
}

struct Device {
	direct: std::fs::File,
	buffered: Option<std::fs::File>,
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
	last: Option<Instant>,
	tty: bool
}

ioctl_read_bad!(blksectget, request_code_none!(0x12, 103), c_ushort);
ioctl_read_bad!(blksszget, request_code_none!(0x12, 104), c_int);
ioctl_read!(blkbszget, 0x12, 112, size_t);
ioctl_write_ptr!(blkbszset, 0x12, 113, size_t);
ioctl_read!(blkgetsize64, 0x12, 114, u64);

impl Device {
	fn open<P: AsRef<std::path::Path>>(path: P, writable: bool, exclusive: bool) -> Result<Self> {
		let direct = std::fs::OpenOptions::new().read(true)
			.custom_flags(libc::O_DIRECT | if exclusive { libc::O_EXCL } else { 0 }).open(path)?;
		let buffered = if writable {
			Some(std::fs::OpenOptions::new().write(true).open(format!("/proc/self/fd/{}", direct.as_raw_fd()))?)
		} else {
			None
		};

		if !direct.metadata()?.file_type().is_block_device() {
			use std::io::ErrorKind;
			return Err(Error::new(ErrorKind::InvalidInput, "File is not a block device"));
		}

		let size = {
			let mut size = 0;
			unsafe { blkgetsize64(direct.as_raw_fd(), &mut size) }?;
			size
		};

		let sector_size = {
			let mut ssz = 0;
			unsafe { blksszget(direct.as_raw_fd(), &mut ssz) }?;
			assert!(ssz > 0);
			usize::try_from(ssz).unwrap()
		};

		// Assert that device size is a multiple of the logical sector size
		assert!(size % sector_size as u64 == 0);

		fn block_size(file: &std::fs::File) -> Result<usize> {
			let mut bsz = 0;
			unsafe { blkbszget(file.as_raw_fd(), &mut bsz) }?;
			assert!(bsz > 0);
			Ok(bsz)
		}

		if block_size(&direct)? != sector_size {
			unsafe { blkbszset(direct.as_raw_fd(), &sector_size) }?;
		}

		// Assert that block size change affects buffered descriptor
		if let Some(ref file) = buffered {
			assert_eq!(block_size(file)?, sector_size);
		}

		let maximum_io = {
			let mut sect = 0;
			unsafe { blksectget(direct.as_raw_fd(), &mut sect) }?;
			assert!(sect > 0);
			sect
		};

		let mut buffer = Vec::with_capacity_in(maximum_io as usize * sector_size, Sensitive);

		// The allocator ensures that the memory is zero‐initialised
		unsafe { buffer.set_len(maximum_io as usize * sector_size); }

		Ok(Self {
			direct,
			buffered,
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

		match self.direct.read_at(&mut buffer[..count as usize * self.sector_size], offset * self.sector_size as u64) {
			Ok(len) => {
				// Assert that we read a multiple of the sector size
				assert!(len % self.sector_size == 0);

				Ok(Some(u16::try_from(len / self.sector_size).unwrap()))
			}

			Err(err) => {
				if err.raw_os_error() == Some(libc::EILSEQ) {
					Ok(None)
				} else {
					Err(err)
				}
			}
		}
	}

	fn zero(&self, offset: u64) -> Result<()> {
		self.buffered.as_ref().unwrap().write_all_at(&self.null, offset * self.sector_size as u64)
	}

	fn flush(&self, offset: u64, count: u16) -> Result<()> {
		use libc::{sync_file_range, off64_t, SYNC_FILE_RANGE_WRITE};

		if let Some(ref file) = self.buffered {
			if unsafe { sync_file_range(file.as_raw_fd(),
				off64_t::try_from(offset * u64::try_from(self.sector_size).unwrap()).unwrap(),
				(count as usize * self.sector_size) as off64_t, SYNC_FILE_RANGE_WRITE) } == 0 {
				Ok(())
			} else {
				Err(Error::last_os_error())
			}
		} else {
			Ok(())
		}
	}

	fn sync(&self) -> Result<()> {
		if let Some(ref file) = self.buffered {
			file.sync_data()
		} else {
			Ok(())
		}
	}

	fn chunks(&self) -> u64 {
		self.sectors.div_ceil(u64::from(self.maximum_io))
	}

	fn iter(&self) -> ChunkIterator<'_> {
		ChunkIterator {
			device: self,
			index: None
		}
	}
}

impl Chunk<'_> {
	fn iter(&self) -> SectorIterator<'_> {
		SectorIterator {
			chunk: self,
			index: None
		}
	}

	fn flush(&self) -> Result<()> {
		self.device.flush(self.index, self.count)
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

				self.index = Some(self.index.unwrap_or(0) + u64::from(len));

				Some(Ok(chunk))
			},
			Ok(None) => {
				let chunk = Chunk {
					device: self.device,
					index: self.index.unwrap_or(0),
					count: self.device.maximum_io,
					valid: false
				};

				self.index = Some(self.index.unwrap_or(0) + u64::from(self.device.maximum_io));

				Some(Ok(chunk))
			},
			Err(err) => Some(Err(err))
		}
	}

	fn size_hint(&self) -> (usize, Option<usize>) {
		let rem = self.device.chunks().saturating_sub(self.index.unwrap_or(0))
		          .div_ceil(u64::from(self.device.maximum_io));
		#[allow(clippy::cast_possible_truncation)]
		(rem as usize, rem.try_into().ok())
	}
}

impl Sector<'_> {
	fn absolute(&self) -> u64 {
		self.chunk.index + u64::from(self.index)
	}

	fn zero(&self) -> Result<()> {
		self.chunk.device.zero(self.absolute())
	}
}

impl SectorIterator<'_> {
	fn absolute(&self) -> u64 {
		self.chunk.index + u64::from(self.index.unwrap_or(0))
	}
}

impl<'t> Iterator for SectorIterator<'t> {
	type Item = Result<Sector<'t>>;

	fn next(&mut self) -> Option<Self::Item> {
		if let Some(index) = self.index
			&& index >= self.chunk.count {
				return None;
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
			u64::from(self.chunk.count.saturating_sub(self.index.unwrap_or(0))),
			self.chunk.device.sectors.saturating_sub(self.absolute())
		);
		#[allow(clippy::cast_possible_truncation)]
		(rem as usize, rem.try_into().ok())
	}
}

impl Progress {
	fn new() -> Result<Self> {
		Ok(Self {
			total: 0,
			error: 0,
			start: Instant::now(),
			last: None,
			tty: stderr().is_terminal()
		})
	}

	fn rate(size: u64, duration: Duration) -> ByteSize {
		ByteSize::b(u64::try_from(u128::from(size) * 1000 / duration.as_millis().max(1)).unwrap())
	}

	fn print(&mut self, dev: &Device, now: Instant) {
		if self.tty {
			eprint!("\x1bM\x1b[K");
		}

		eprintln!("{:>3} %   {:>9} / {}   {:>9} / s   {} corrupt sectors",
		          self.total * 100 / dev.sectors,
		          ByteSize::b(self.total * dev.sector_size as u64),
		          ByteSize::b(dev.sectors * dev.sector_size as u64),
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

	if opt.idle {
		use ioprio::{set_priority, Target, Pid, Priority, Class};
		set_priority(Target::Process(Pid::this()), Priority::new(Class::Idle)).unwrap();
	}

	let dev = Device::open(&opt.device, !opt.dry_run, !opt.force)?;

	let mut prog = Progress::new()?;

	if !opt.quiet {
		eprintln!();
		prog.print_now(&dev);
	}

	for chunk in dev.iter() {
		let chunk = chunk?;

		if !opt.quiet {
			prog.print_50(&dev);
		}

		if !chunk.valid {
			for sector in chunk.iter() {
				let sector = sector?;

				if !sector.valid {
					prog.error += 1;

					if opt.enumerate {
						println!("{}", sector.absolute());
					}

					if !opt.dry_run {
						sector.zero()?;
					}
				}
			}

			chunk.flush()?;
		}

		prog.total += u64::from(chunk.count);
	}

	if !opt.quiet {
		prog.print_now(&dev);
	}

	dev.sync()
}
