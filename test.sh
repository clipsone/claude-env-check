#!/bin/bash
set -euo pipefail

project_dir="$(cd "$(dirname "$0")" && pwd)"
tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/claude-envcheck-test.XXXXXXXX")"
trap 'rm -rf "$tmp_dir"' EXIT

# Compile all non-App-entrypoint Swift modules + Tests/RunAllTests.swift under Swift 6 strict mode
source_files=()
for file in "$project_dir"/Sources/*.swift; do
    base="$(basename "$file")"
    if [ "$base" = "EnvironmentCheckApp.swift" ] || [ "$base" = "ClashSymbiosisView.swift" ] || [ "$base" = "WorkbenchView.swift" ]; then
        continue
    fi
    source_files+=("$file")
done

/usr/bin/xcrun swiftc \
    -swift-version 6 \
    -target arm64-apple-macos13.0 \
    -parse-as-library \
    -warnings-as-errors \
    "${source_files[@]}" \
    "$project_dir/Tests/RunAllTests.swift" \
    -o "$tmp_dir/RunAllTests"

"$tmp_dir/RunAllTests" "$@"
