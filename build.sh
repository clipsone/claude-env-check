#!/bin/bash
set -euo pipefail

make_dmg=0
install_app=0
run_tests=0
sign_identity="-"

while [ "$#" -gt 0 ]; do
    case "$1" in
        --dmg) make_dmg=1 ;;
        --install) install_app=1 ;;
        --test) run_tests=1 ;;
        --sign)
            shift
            if [ "$#" -eq 0 ]; then
                printf 'Missing identity after --sign\n' >&2
                exit 2
            fi
            sign_identity="$1"
            ;;
        *)
            printf 'Unknown option: %s\nUsage: bash build.sh [--test] [--dmg] [--install] [--sign "<Identity>"]\n' "$1" >&2
            exit 2
            ;;
    esac
    shift
done

project_dir="$(cd "$(dirname "$0")" && pwd)"

if [ "$run_tests" -eq 1 ]; then
    bash "$project_dir/test.sh"
fi

output_dir="$project_dir/build"
mkdir -p "$output_dir"
staging_dir="$(mktemp -d "$output_dir/.staging.XXXXXXXX")"
trap 'rm -rf "$staging_dir"' EXIT

version="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$project_dir/Info.plist")"
app_name="Claude 环境体检.app"
staging_app="$staging_dir/$app_name"
mkdir -p "$staging_app/Contents/MacOS" "$staging_app/Contents/Resources"
/bin/cp "$project_dir/Info.plist" "$staging_app/Contents/Info.plist"
if [ -f "$project_dir/Resources/AppIcon.icns" ]; then
    /bin/cp "$project_dir/Resources/AppIcon.icns" "$staging_app/Contents/Resources/AppIcon.icns"
fi
/usr/bin/xcrun swiftc \
    -swift-version 6 \
    -target arm64-apple-macos13.0 \
    -parse-as-library \
    -warnings-as-errors \
    -O \
    "$project_dir"/Sources/*.swift \
    -o "$staging_app/Contents/MacOS/ClaudeEnvironmentCheck"

if [ "$sign_identity" = "-" ]; then
    /usr/bin/codesign --force --sign - "$staging_app"
else
    /usr/bin/codesign --force --options runtime --timestamp --sign "$sign_identity" "$staging_app"
fi
/usr/bin/codesign --verify --strict "$staging_app"

rm -rf "$output_dir/$app_name"
/usr/bin/ditto "$staging_app" "$output_dir/$app_name"
printf 'Built app: %s\n' "$output_dir/$app_name"

if [ "$install_app" -eq 1 ]; then
    target_app="/Applications/$app_name"
    rm -rf "$target_app"
    /usr/bin/ditto "$output_dir/$app_name" "$target_app"
    /usr/bin/codesign --verify --strict "$target_app"
    printf 'Installed: %s\n' "$target_app"
fi

if [ "$make_dmg" -eq 1 ]; then
    dmg_staging="$staging_dir/dmg-root"
    mkdir -p "$dmg_staging"
    /usr/bin/ditto "$output_dir/$app_name" "$dmg_staging/$app_name"
    ln -s /Applications "$dmg_staging/Applications"
    dmg_path="$output_dir/Claude-Environment-Check-${version}-arm64.dmg"
    rm -f "$dmg_path"
    /usr/bin/hdiutil create \
        -volname "Claude 环境体检 ${version}" \
        -srcfolder "$dmg_staging" \
        -ov \
        -format UDZO \
        "$dmg_path" >/dev/null
    printf 'Packaged DMG: %s\n' "$dmg_path"
fi
