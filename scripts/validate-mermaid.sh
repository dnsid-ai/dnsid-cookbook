#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -eq 0 ]; then
    files=()
    while IFS= read -r file; do
        files+=("$file")
    done < <(find recipes -name architecture.md -print | sort)
else
    files=("$@")
fi

if [ "${#files[@]}" -eq 0 ]; then
    echo "No markdown files to validate."
    exit 0
fi

if [ -n "${MMDC_BIN:-}" ]; then
    mmdc_cmd=("$MMDC_BIN")
elif command -v mmdc >/dev/null 2>&1; then
    mmdc_cmd=(mmdc)
else
    if ! command -v npm >/dev/null 2>&1; then
        echo "Error: neither mmdc nor npm is available." >&2
        exit 1
    fi

    if [ -z "${PUPPETEER_EXECUTABLE_PATH:-}" ]; then
        for browser in \
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
            "/Applications/Chromium.app/Contents/MacOS/Chromium" \
            "/usr/bin/google-chrome" \
            "/usr/bin/chromium" \
            "/usr/bin/chromium-browser"; do
            if [ -x "$browser" ]; then
                export PUPPETEER_EXECUTABLE_PATH="$browser"
                export PUPPETEER_SKIP_DOWNLOAD="${PUPPETEER_SKIP_DOWNLOAD:-true}"
                break
            fi
        done
    fi

    mmdc_package=${MMDC_NPM_PACKAGE:-@mermaid-js/mermaid-cli@11.15.0}
    mmdc_cmd=(npm exec --yes --package "$mmdc_package" -- mmdc)
fi

tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/validate-mermaid.XXXXXX")
trap 'rm -rf "$tmpdir"' EXIT

puppeteer_config="$tmpdir/puppeteer-config.json"
cat > "$puppeteer_config" <<'JSON'
{
  "args": ["--no-sandbox", "--disable-setuid-sandbox"]
}
JSON

start_re='^```mermaid[[:space:]]*$'
end_re='^```'
block_files=()
block_numbers=()
block_inputs=()

for file in "${files[@]}"; do
    if [ ! -f "$file" ]; then
        echo "Error: not a file: $file" >&2
        exit 1
    fi

    safe_name=${file//[^A-Za-z0-9_.-]/_}
    block_number=0
    in_block=0
    output_file=""

    while IFS= read -r line || [ -n "$line" ]; do
        if [ "$in_block" -eq 0 ] && [[ "$line" =~ $start_re ]]; then
            block_number=$((block_number + 1))
            output_file="$tmpdir/${safe_name}.block-${block_number}.mmd"
            : > "$output_file"
            block_files+=("$file")
            block_numbers+=("$block_number")
            block_inputs+=("$output_file")
            in_block=1
            continue
        fi

        if [ "$in_block" -eq 1 ] && [[ "$line" =~ $end_re ]]; then
            in_block=0
            continue
        fi

        if [ "$in_block" -eq 1 ]; then
            printf '%s\n' "$line" >> "$output_file"
        fi
    done < "$file"

    if [ "$in_block" -eq 1 ]; then
        echo "Error: unclosed Mermaid block in $file" >&2
        exit 1
    fi
done

if [ "${#block_inputs[@]}" -eq 0 ]; then
    echo "No Mermaid blocks found."
    exit 0
fi

failures=0

for i in "${!block_inputs[@]}"; do
    file=${block_files[$i]}
    block_number=${block_numbers[$i]}
    input_file=${block_inputs[$i]}
    output_svg="$tmpdir/rendered-$i.svg"
    log_file="$tmpdir/rendered-$i.log"

    if "${mmdc_cmd[@]}" -i "$input_file" -o "$output_svg" -p "$puppeteer_config" >"$log_file" 2>&1; then
        echo "OK: $file Mermaid block $block_number"
    else
        echo "FAIL: $file Mermaid block $block_number" >&2
        sed 's/^/    /' "$log_file" >&2
        failures=1
    fi
done

if [ "$failures" -ne 0 ]; then
    exit 1
fi

echo "Validated ${#block_inputs[@]} Mermaid block(s)."
