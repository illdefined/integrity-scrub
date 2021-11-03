## Synopsis

This tool attempts to read all logical sectors of a block device, overwriting any sector that cannot be read due to an
I/O error with zeros. It is intended to restore Linux dm-integrity volumes with invalid (corrupted) integrity tags.

## Usage

If you wish to scrub a volume, consider creating a backup of the underlying physical device first.

Then run the tool with the volume device path (`/dev/mapper/…` or `/dev/dm-…`) as its single command‐line argument.

Unless you really know what you are doing, you should not run it on a mounted volume. Data written by the filesystem
might get overwritten by interleaved writes of the tool.

## Implementation notes

The block device is first read in large chunks (the maximum sectors per request as reported by the `BLKSECTGET` ioctl).
If a read results in an I/O error (`EIO`), the logical sectors in the chunk are read individually and any sector that
results in an I/O error is overwritten with zeros.

## Caveat

This tool might delete all your data and summon a seal. Use it at your own risk. The seal will demand fish.

If you are not using a filesystem with copy‐on‐write semantics or data journalling, you should probably rely on
dm-integrity’s data journal.
