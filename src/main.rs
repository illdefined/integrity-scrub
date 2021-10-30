use std::io::Result;
use std::os::unix::fs::{FileExt, FileTypeExt};
use std::os::unix::io::{AsRawFd, RawFd};
use std::process::exit;

use libc::{c_ushort, c_int};
use nix::fcntl::{posix_fadvise, PosixFadviseAdvice};
use nix::{ioctl_read, ioctl_read_bad, request_code_none};

ioctl_read_bad!(blksectget, request_code_none!(0x12, 103), c_ushort);
ioctl_read_bad!(blksszget, request_code_none!(0x12, 104), c_int);
ioctl_read!(blkgetsize64, 0x12, 114, u64);

fn willneed(fd: RawFd, offset: u64, len: u64) -> Result<()> {
	for advice in [
		PosixFadviseAdvice::POSIX_FADV_SEQUENTIAL,
		PosixFadviseAdvice::POSIX_FADV_NOREUSE,
		PosixFadviseAdvice::POSIX_FADV_WILLNEED] {
		posix_fadvise(fd, offset.try_into().unwrap(), len.try_into().unwrap(), advice).map(|_| ())?;
	}

	Ok(())
}

fn main() -> Result<()> {
	let mut args = std::env::args();

	if args.len() != 2 {
		eprintln!("Usage: {} [device]", args.next().unwrap());
		exit(64);
	}

	let path = args.nth(1).unwrap();

	let dev = std::fs::OpenOptions::new()
	.read(true)
	.write(true)
	.open(&path)
	.unwrap_or_else(|err| {
		eprintln!("Failed to open {}: {}", path, err);
		exit(66);
	});

	let meta = dev.metadata().unwrap_or_else(|err| {
		eprintln!("Unable to query metadata on {}: {}", path, err);
		exit(66);
	});

	if !meta.file_type().is_block_device() {
		eprintln!("{} is not a block device", path);
		exit(66);
	}

	let size = {
		let mut size = u64::MAX;
		unsafe {
			blkgetsize64(dev.as_raw_fd(), &mut size)
		}.unwrap_or_else(|err| {
			eprintln!("Unable to determine device size for {}: {}", path, err);
			exit(74);
		});

		size
	};

	let ssz = {
		let mut ssz = -1;
		unsafe {
			blksszget(dev.as_raw_fd(), &mut ssz)
		}.unwrap_or_else(|err| {
			eprintln!("Unable to determine logical sector size for {}: {}", path, err);
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
			eprintln!("Unable to determine maximum I/O size for {}: {}", path, err);
			exit(74);
		});

		assert!(sect > 0);
		sect as usize
	};

	// Assert that device size is a multiple of the logical sector size
	assert!(size % ssz as u64 == 0);

	let null = vec![0u8; ssz];
	let mut buffer = vec![0u8; sect * ssz];

	willneed(dev.as_raw_fd(), 0, 0).unwrap_or_else(|err| {
		eprintln!("Failed to predeclare access pattern for {}: {}", path, err);
		exit(74);
	});

	let mut offset = 0u64;
	let mut verify = 0usize;
	let mut sync;

	println!();

	loop {
		if verify == 0 {
			eprintln!("\x1bM\x1b[K{:>3} %  {:>11} / {}", offset * 100 / size,
			          bytesize::to_string(offset, true), bytesize::to_string(size, true));
		}

		// Synchronise to device if last sector of range
		sync = verify == 1;

		match dev.read_at(if verify == 0 { &mut buffer } else { &mut buffer[0..ssz] }, offset) {
			Ok(0) => { break; }
			Ok(len) => {
				// Assert that we read a multiple of the sector size
				assert!(len % ssz == 0);

				offset += len as u64;
				verify = verify.saturating_sub(1);
			}

			Err(err) => {
				if let Some(libc::EIO) = err.raw_os_error() {
					if verify == 0 {
						verify = sect;

						// Declare our intention to re‐read the range
						willneed(dev.as_raw_fd(), offset, (sect * ssz) as u64).unwrap_or_else(|err| {
							eprintln!("Failed to predeclare access pattern for range: {}", err);
							exit(74);
						});

						continue;
					}

					eprintln!("Zeroing logical sector {}\n", offset / ssz as u64);
					let len = dev.write_at(&null, offset).unwrap_or_else(|err| {
						eprintln!("Write error at {}: {}", offset, err);
						exit(74);
					});

					// Assert that we wrote a complete sector
					assert_eq!(len, ssz);

					offset += ssz as u64;
					verify -= 1;
				} else {
					eprintln!("Read error at {}: {}", offset, err);
					exit(74);
				}
			}
		}

		if sync {
			dev.sync_data().unwrap_or_else(|err| {
				eprintln!("Failed to synchronise data to device: {}", err);
				exit(74);
			});
		}
	}

	Ok(())
}
