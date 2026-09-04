#!/usr/bin/env bash
#
# Carve logical partitions from super.pak and unpack squashfs images with epk2extract.
#
# Usage:
#   ./unpack-super.sh [extraction-directory]
#
# Default extraction directory: 33.31.68.01-HE_DTV_W25G_AFABATAA
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXTRACT_DIR="${1:-$SCRIPT_DIR/33.31.68.01-HE_DTV_W25G_AFABATAA}"
SUPER_PAK="$EXTRACT_DIR/super.pak"
DPMETA_PAK="$EXTRACT_DIR/dpmeta.pak"
SECTOR_SIZE=512

log() {
	printf '==> %s\n' "$*"
}

die() {
	printf 'error: %s\n' "$*" >&2
	exit 1
}

find_epk2extract() {
	local build_dir binary
	for build_dir in build_osx build_linux build_cygwin; do
		binary="$SCRIPT_DIR/$build_dir/epk2extract"
		if [[ -x "$binary" ]]; then
			printf '%s' "$binary"
			return 0
		fi
	done
	return 1
}

run_epk2extract() {
	local binary="$1"
	local input="$2"
	local runner=("$binary" "$input")

	if [[ "$(uname -s)" == "Linux" ]] && command -v fakeroot >/dev/null 2>&1; then
		runner=(fakeroot "${runner[@]}")
	fi

	"${runner[@]}"
}

parse_partitions() {
	local dpmeta="$1"
	local line name size offset output

	if [[ ! -f "$dpmeta" ]]; then
		die "missing $dpmeta (needed to read partition offsets)"
	fi

	while IFS= read -r line; do
		# Example: rootfs-linear,,,ro, 0 3292320 linear /dev/mmcblk0p28 2048
		# The first entry may be prefixed with dm-mod.create=" (see strings dpmeta.pak).
		if [[ "$line" =~ ([a-z]+)-linear,,,ro,\ 0\ ([0-9]+)\ linear\ /dev/mmcblk0p28\ ([0-9]+) ]]; then
			name="${BASH_REMATCH[1]}"
			size="${BASH_REMATCH[2]}"
			offset="${BASH_REMATCH[3]}"
			output="$EXTRACT_DIR/${name}.pak"
			printf '%s %s %s %s\n' "$name" "$offset" "$size" "$output"
		fi
	done < <(strings "$dpmeta" | tr ';' '\n' | grep -oE '[a-z]+-linear,,,ro, 0 [0-9]+ linear /dev/mmcblk0p28 [0-9]+')
}

carve_partition() {
	local super="$1"
	local offset="$2"
	local size="$3"
	local output="$4"

	if [[ -f "$output" ]]; then
		log "already carved: $(basename "$output") (remove it to re-carve)"
		return 0
	fi

	log "carving $(basename "$output") (sector $offset, count $size)"
	dd if="$super" of="$output" bs="$SECTOR_SIZE" skip="$offset" count="$size" status=none
}

unpack_partition() {
	local epk2extract="$1"
	local carved="$2"
	local unpacked="${carved}.unsquashfs"

	if [[ -d "$unpacked" ]]; then
		log "already unpacked: $(basename "$unpacked") (remove it to re-unpack)"
		return 0
	fi

	log "unpacking $(basename "$carved")"
	run_epk2extract "$epk2extract" "$carved"
}

main() {
	local epk2extract
	local partitions=()
	local name offset size output carved_count=0 unpacked_count=0

	[[ -d "$EXTRACT_DIR" ]] || die "extraction directory not found: $EXTRACT_DIR"
	[[ -f "$SUPER_PAK" ]] || die "missing $SUPER_PAK"
	epk2extract="$(find_epk2extract)" || die "epk2extract not found; run: ./build.sh"

	log "extraction directory: $EXTRACT_DIR"
	log "using epk2extract: $epk2extract"

	while IFS= read -r line; do
		[[ -n "$line" ]] && partitions+=("$line")
	done < <(parse_partitions "$DPMETA_PAK")

	[[ "${#partitions[@]}" -gt 0 ]] || die "no partitions found in $DPMETA_PAK"

	log "found ${#partitions[@]} partition(s) in dpmeta.pak"

	for entry in "${partitions[@]}"; do
		read -r name offset size output <<<"$entry"
		carve_partition "$SUPER_PAK" "$offset" "$size" "$output"
		((carved_count += 1)) || true
	done

	for entry in "${partitions[@]}"; do
		read -r _ _ _ output <<<"$entry"
		unpack_partition "$epk2extract" "$output"
		((unpacked_count += 1)) || true
	done

	log "done: carved $carved_count partition(s), unpacked $unpacked_count partition(s)"
	log "browse rootfs at: $EXTRACT_DIR/rootfs.pak.unsquashfs/"
}

main "$@"