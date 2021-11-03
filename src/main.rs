#![feature(allocator_api)]

use std::io::Error;
use std::os::unix::fs::{FileExt, FileTypeExt};
use std::os::unix::io::AsRawFd;
use std::process::exit;
use std::vec::Vec;

use clap::Parser;
use libc::{c_ushort, c_int};
use libc::{sync_file_range, SYNC_FILE_RANGE_WRITE};
use nix::fcntl::{posix_fadvise, PosixFadviseAdvice};
use nix::{ioctl_read, ioctl_read_bad, request_code_none};
use sensitive::alloc::Sensitive;

#[derive(Parser)]
struct Opt {
	/// Device path
	#[clap(parse(from_os_str), value_hint = clap::ValueHint::FilePath)]
	device: std::path::PathBuf,

	/// Increase verbosity
	#[clap(short, long)]
	verbose: bool
}

ioctl_read_bad!(blksectget, request_code_none!(0x12, 103), c_ushort);
ioctl_read_bad!(blksszget, request_code_none!(0x12, 104), c_int);
ioctl_read!(blkgetsize64, 0x12, 114, u64);

fn main() -> std::io::Result<()> {
	let opt = Opt::parse();

	let path = opt.device;

	let dev = std::fs::OpenOptions::new()
	.read(true)
	.write(true)
	.open(&path)
	.unwrap_or_else(|err| {
		eprintln!("Failed to open {}: {}", path.display(), err);
		exit(66);
	});

	let meta = dev.metadata().unwrap_or_else(|err| {
		eprintln!("Unable to query metadata on {}: {}", path.display(), err);
		exit(66);
	});

	if !meta.file_type().is_block_device() {
		eprintln!("{} is not a block device", path.display());
		exit(66);
	}

	let size = {
		let mut size = u64::MAX;
		unsafe {
			blkgetsize64(dev.as_raw_fd(), &mut size)
		}.unwrap_or_else(|err| {
			eprintln!("Unable to determine device size for {}: {}", path.display(), err);
			exit(74);
		});

		size
	};

	let ssz = {
		let mut ssz = -1;
		unsafe {
			blksszget(dev.as_raw_fd(), &mut ssz)
		}.unwrap_or_else(|err| {
			eprintln!("Unable to determine logical sector size for {}: {}", path.display(), err);
			exit(74);
		});

		assert!(ssz > 0);
		ssz as usize
	};

	let sect = {
		let mut sect = c_ushort::MAX;
		unsafe {
			blksectget(dev.as_raw_fd(), &mut sect)
		}.unwrap_or_else(|err| {
			eprintln!("Unable to determine maximum I/O size for {}: {}", path.display(), err);
			exit(74);
		});

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
		posix_fadvise(dev.as_raw_fd(), 0, 0, advice).unwrap_or_else(|err| {
			eprintln!("Failed to predeclare access pattern for {}: {}", path.display(), err);
			exit(74);
		});
	}

	let mut offset = 0u64;
	let mut verify = 0usize;
	let mut zeroed = 0u64;
	let mut flush: Option<u64> = None;

	println!();

	loop {
		if verify == 0 {
			eprintln!("\x1bM\x1b[K{:>3} %  {:>11} / {}  ({} sectors corrected)", offset * 100 / size,
			          bytesize::to_string(offset, true), bytesize::to_string(size, true), zeroed);
		}

		match dev.read_at(if verify == 0 { &mut buffer } else { &mut buffer[0..ssz] }, offset) {
			Ok(0) => { break; }
			Ok(len) => {
				// Assert that we read a multiple of the sector size
				assert!(len % ssz == 0);

				if verify == 0 {
					posix_fadvise(dev.as_raw_fd(), offset.try_into().unwrap(), len.try_into().unwrap(),
					              PosixFadviseAdvice::POSIX_FADV_DONTNEED)
					.unwrap_or_else(|err| {
						eprintln!("Failed to declare sector range as no longer used: {}", err);
						exit(74);
					});
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

					if opt.verbose {
						eprintln!("Zeroing logical sector {}\n", offset / ssz as u64);
					}

					let len = dev.write_at(&null, offset).unwrap_or_else(|err| {
						eprintln!("Write error at {}: {}", offset, err);
						exit(74);
					});

					// Assert that we wrote a complete sector
					assert_eq!(len, ssz);

					// Remember first sector to flush
					if flush.is_none() {
						flush = Some(offset);
					}

					offset += ssz as u64;
					verify -= 1;
					zeroed += 1;
				} else {
					eprintln!("Read error at {}: {}", offset, err);
					exit(74);
				}
			}
		}

		if let Some(start) = flush {
			if unsafe {
				sync_file_range(dev.as_raw_fd(), start.try_into().unwrap(),
				                (offset - start).try_into().unwrap(),
				                SYNC_FILE_RANGE_WRITE)
			} != 0 {
				eprintln!("Failed to flush data to device: {}", Error::last_os_error());
				exit(74);
			}

			flush = None;
		}
	}

	Ok(())
}
