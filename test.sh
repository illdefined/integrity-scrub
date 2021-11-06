#!/bin/sh

set -e -u

for sector_size in 512 1024 2048 4096; do
	echo Sector size "$sector_size"

	tmp="$(mktemp)"
	trap 'rm -f -- "$tmp"' EXIT HUP INT QUIT TERM

	truncate --size 4G "$tmp"
	integritysetup format --batch-mode --no-wipe --journal-size 0 --sector-size "$sector_size" --integrity crc32c "$tmp"

	dm="$(mktemp -u tmp-XXXXXXXXXX)"
	integritysetup open --batch-mode "$tmp" "$dm"
	trap 'integritysetup close "$dm"; rm -f -- "$tmp"' EXIT HUP INT QUIT TERM

	if cat "/dev/mapper/$dm" >/dev/null; then
		exit 1
	fi

	target/debug/integrity-scrub -n "/dev/mapper/$dm"

	if cat "/dev/mapper/$dm" >/dev/null; then
		exit 1
	fi

	target/debug/integrity-scrub "/dev/mapper/$dm"

	if ! cat "/dev/mapper/$dm" >/dev/null; then
		exit 1
	fi

	target/debug/integrity-scrub "/dev/mapper/$dm"

	integritysetup close "$dm"
	rm -f -- "$tmp"
	trap - EXIT HUP INT QUIT TERM
done
