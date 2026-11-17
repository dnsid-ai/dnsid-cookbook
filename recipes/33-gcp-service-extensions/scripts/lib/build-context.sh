# shellcheck shell=bash
# The image build's upload (scripts/deploy.sh submits it to Cloud Build): an allowlist, copied file by file into an
# empty directory, so nothing else in the working tree (Terraform state, keys, certificates, local settings, plan
# records, tests, node_modules) can be uploaded by accident. Sourced by scripts/deploy.sh and by the local tests.

# The files and directories, relative to the integration's root. Directories are copied with every regular file in
# them; src/ and proto/ hold only the verifier's source and its vendored schemas.
BUILD_CONTEXT_FILES=(
  cloudbuild.yaml
  Dockerfile
  .dockerignore
  package.json
  package-lock.json
  .npmrc
  .nvmrc
  LICENSE
  src
  proto
  origin/Dockerfile
  origin/.dockerignore
  origin/package.json
  origin/server.ts
  origin/LICENSE
  scripts/container-smoke.sh
  scripts/lib/container-cleanup.sh
  tests/container/probe.ts
  tests/support/grpc-client.ts
  tests/support/http-client.ts
  tests/support/response-wire.ts
  tests/support/signing.ts
)

# assemble_build_context ROOT DEST: copies the allowlist from ROOT into DEST, which must be empty. Fails if an entry is
# missing, or if anything copied is a symbolic link, a key, a certificate, Terraform state or an environment file.
assemble_build_context() {
  local root="$1" dest="$2" entry
  [[ -d "$dest" && -z "$(ls -A "$dest")" ]] || { echo "build context: $dest is not an empty directory" >&2; return 1; }
  for entry in "${BUILD_CONTEXT_FILES[@]}"; do
    if [[ -f "$root/$entry" && ! -L "$root/$entry" ]]; then
      mkdir -p "$dest/$(dirname "$entry")"
      cp -p "$root/$entry" "$dest/$entry"
    elif [[ -d "$root/$entry" && ! -L "$root/$entry" ]]; then
      local odd
      odd="$(cd "$root" && find "$entry" ! -type f ! -type d -print)"
      [[ -z "$odd" ]] || { echo "build context: refusing to upload what is not a regular file: ${odd//$'\n'/ }" >&2; return 1; }
      mkdir -p "$dest/$entry"
      (cd "$root" && find "$entry" -type f -print0) | while IFS= read -r -d '' file; do
        mkdir -p "$dest/$(dirname "$file")"
        cp -p "$root/$file" "$dest/$file"
      done
    else
      echo "build context: $entry is missing or is not a regular file or directory" >&2
      return 1
    fi
  done
  local unsafe
  unsafe="$(cd "$dest" && find . \( -type l -o -name '*.pem' -o -name '*.key' -o -name '*.p12' -o -name '*.pfx' -o -name '*.jwk' \
    -o -name '*.tfstate*' -o -name '.env' -o -name '.env.*' -o -name '*.tfvars*' -o -name 'node_modules' \) -print)"
  [[ -z "$unsafe" ]] || { echo "build context: refusing to upload: ${unsafe//$'\n'/ }" >&2; return 1; }
  # An explicit, empty ignore file: gcloud uploads exactly this directory and never falls back to other ignore rules.
  printf '# Everything here was copied from an allowlist (scripts/lib/build-context.sh); nothing is excluded.\n' > "$dest/.gcloudignore"
  # Fixed permissions, whatever the caller's umask (scripts/deploy.sh runs under 077) or the checkout's modes: Docker
  # copies a directory's modes into the image, and the images run as uid 1000, which must read every file. Directories
  # 755, files 644, and the executables (the smoke script) stay 755. Nothing here is secret; the checks above see to it.
  chmod -R u=rwX,go=rX "$dest"
}
