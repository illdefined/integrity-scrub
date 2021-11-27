#!/bin/sh

set -e -u

msg() {
	printf '\x1b[1m%s\x1b[0m\n' "$1"
}

perform() {
	msg "Attempting read, expecting failure"
	if pv "/dev/mapper/$dm" >/dev/null; then
		exit 1
	fi
	echo

	msg "Scrub dry run, expecting lots of corrupt sectors"
	"target/$profile/integrity-scrub" -n "/dev/mapper/$dm"
	echo

	msg "Attempting read, expecting failure"
	if pv "/dev/mapper/$dm" >/dev/null; then
		exit 1
	fi
	echo

	msg "Scrub, expecting lots of corrupt sectors"
	"target/$profile/integrity-scrub" "/dev/mapper/$dm"
	echo

	msg "Attempting read, expecting success"
	pv "/dev/mapper/$dm" >/dev/null
	echo

	msg "Scrub again, expecting no corrupt sectors"
	"target/$profile/integrity-scrub" "/dev/mapper/$dm"
	echo

	msg "Trying to corrupt single sector"
	blockdev --flushbufs "/dev/mapper/$dm"
	blockdev --flushbufs "$loop"
	dd if=/dev/urandom of="$loop" bs=16 count=1 seek="$((device_size / 16 / 4))MiB" conv=fdatasync
	echo

	msg "Attemping to read, expecting failure"
	if pv "/dev/mapper/$dm" >/dev/null; then
		exit 1
	fi
	echo

	msg "Scrub, expecting single corrupt sector"
	"target/$profile/integrity-scrub" "/dev/mapper/$dm"
	echo

	msg "Attemping to read, expecting success"
	pv "/dev/mapper/$dm" >/dev/null
	echo
}

profile="${profile:-debug}"

for sector_size in 512 1024 2048 4096; do
	device_size="$((sector_size))"
	msg "Profile $profile, sector size $sector_size, device size $device_size MiB"

	tmp="$(mktemp)"
	trap 'rm -f -- "$tmp"' EXIT HUP INT QUIT TERM

	truncate --size "${device_size}MiB" "$tmp"
	loop="$(losetup --show -f "$tmp")"
	trap 'losetup -d "$loop"; rm -f -- "$tmp"' EXIT HUP INT QUIT TERM

	msg "Trying integritysetup with CRC32c"

	integritysetup format --batch-mode --no-wipe --journal-size 0 --sector-size "$sector_size" \
	--integrity crc32c "$loop"

	dm="$(mktemp -u tmp-XXXXXXXXXX)"
	integritysetup open --batch-mode "$tmp" "$dm"
	trap 'integritysetup close "$dm"; losetup -d "$loop"; rm -f -- "$tmp"' EXIT HUP INT QUIT TERM
	echo

	perform

	integritysetup close "$dm"

	msg "Trying cryptsetup with AEGIS-128"

	key="$(mktemp)"
	mktemp -u XXXXXXXXXXXX >"$key"
	trap 'rm -f -- "$key"; losetup -d "$loop"; rm -f -- "$tmp"' EXIT HUP INT QUIT TERM

	wipefs -a "$loop"
	cryptsetup luksFormat --batch-mode --type luks2 --cipher aegis128-random --key-size 128 --key-file "$key" \
	--force-password --integrity aead --integrity-no-journal --integrity-no-wipe --sector-size "$sector_size" "$loop"

	cryptsetup open --batch-mode --integrity-no-journal --key-file "$key" "$loop" "$dm"
	trap 'cryptsetup close "$dm"; rm -f -- "$key"; losetup -d "$loop"; rm -f -- "$tmp"' EXIT HUP INT QUIT TERM
	echo

	perform

	cryptsetup close "$dm"
	rm -f -- "$key"
	losetup -d "$loop"
	rm -f -- "$tmp"
	trap - EXIT HUP INT QUIT TERM
	echo
done
