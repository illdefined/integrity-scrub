#![feature(allocator_api)]

use std::io::Error;
use std::os::unix::fs::{FileExt, FileTypeExt};
use std::os::unix::io::AsRawFd;
use std::process::exit;
use std::time::{Duration, Instant};
use std::vec::Vec;

use clap::Parser;
use libc::{c_ushort, c_int};
use libc::{sync_file_range, SYNC_FILE_RANGE_WRITE};
use nix::fcntl::{posix_fadvise, PosixFadviseAdvice};
use nix::{ioctl_read, ioctl_read_bad, request_code_none};
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

ioctl_read_bad!(blksectget, request_code_none!(0x12, 103), c_ushort);
ioctl_read_bad!(blksszget, request_code_none!(0x12, 104), c_int);
ioctl_read!(blkgetsize64, 0x12, 114, u64);

fn rate(size: u64, duration: Duration) -> String {
	bytesize::to_string((size as u128 * 1000 / duration.as_millis().max(1)) as u64, true)
}

fn main() -> std::io::Result<()> {
	let opt = Opt::parse();

	let dev = std::fs::OpenOptions::new()
	.read(true)
	.write(!opt.dry_run)
	.open(&opt.device)
	.unwrap_or_else(|err| {
		eprintln!("Failed to open {}: {}", opt.device.display(), err);
		exit(66);
	});

	let meta = dev.metadata()?;

	if !meta.file_type().is_block_device() {
		eprintln!("{} is not a block device", opt.device.display());
		exit(66);
	}

	let size = {
		let mut size = u64::MAX;
		unsafe { blkgetsize64(dev.as_raw_fd(), &mut size) }?;

		size
	};

	let ssz = {
		let mut ssz = -1;
		unsafe { blksszget(dev.as_raw_fd(), &mut ssz) }?;

		assert!(ssz > 0);
		ssz as usize
	};

	let sect = {
		let mut sect = c_ushort::MAX;
		unsafe { blksectget(dev.as_raw_fd(), &mut sect) }?;

		assert!(sect > 0);
		sect as usize
	};

	// Assert that device size is a multiple of the logical sector size
	assert!(size % ssz as u64 == 0);

	let null = vec![0u8; ssz];
	let mut buffer = Vec::with_capacity_in(sect * ssz, Sensitive);

	// The allocator ensures that the memory is zero‐initialised
	unsafe { buffer.set_len(sect * ssz); }

	for advice in [
		PosixFadviseAdvice::POSIX_FADV_SEQUENTIAL,
		PosixFadviseAdvice::POSIX_FADV_WILLNEED] {
		posix_fadvise(dev.as_raw_fd(), 0, 0, advice)?;
	}

	let mut offset = 0u64;
	let mut verify = 0usize;
	let mut errors = 0u64;
	let mut flush: Option<u64> = None;

	eprintln!();

	let start = Instant::now();
	let mut last = start;

	loop {
		let now = Instant::now();

		if verify == 0 && now.duration_since(last) > Duration::from_millis(50) {
			eprintln!("\x1bM\x1b[K{:>3} %   {:>9} / {}   {:>9} / s   {} corrupt sectors", offset * 100 / size,
			          bytesize::to_string(offset, true), bytesize::to_string(size, true),
			          rate(offset, last.duration_since(now)), errors);
			last = now;
		}

		match dev.read_at(if verify == 0 { &mut buffer } else { &mut buffer[0..ssz] }, offset) {
			Ok(0) => { break; }
			Ok(len) => {
				// Assert that we read a multiple of the sector size
				assert!(len % ssz == 0);

				if verify == 0 {
					posix_fadvise(dev.as_raw_fd(), offset.try_into().unwrap(), len.try_into().unwrap(),
					              PosixFadviseAdvice::POSIX_FADV_DONTNEED)?;
				}

				offset += len as u64;
				verify = verify.saturating_sub(1);
			}
			Err(err) => {
				if let Some(libc::EIO) = err.raw_os_error() {
					if verify == 0 {
						verify = sect;
						continue;
					}

					errors += 1;

					let len = if !opt.dry_run {
						dev.write_at(&null, offset)?
					} else {
						null.len()
					};

					// Assert that we wrote a complete sector
					assert_eq!(len, ssz);

					// Remember first sector to flush
					if flush.is_none() {
						flush = Some(offset);
					}

					offset += ssz as u64;
					verify -= 1;
				} else {
					return Err(err);
				}
			}
		}

		if verify == 0 {
			if let Some(start) = flush {
				if unsafe {
					sync_file_range(dev.as_raw_fd(), start.try_into().unwrap(),
					                (offset - start).try_into().unwrap(),
					                SYNC_FILE_RANGE_WRITE)
				} != 0 {
					return Err(Error::last_os_error());
				}

				flush = None;
			}
		}
	}

	dev.sync_data()
}
