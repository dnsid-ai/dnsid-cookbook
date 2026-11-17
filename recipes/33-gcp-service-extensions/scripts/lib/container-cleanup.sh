# shellcheck shell=bash
# Cleanup for scripts/container-smoke.sh, sourced by it and by tests/unit/container-cleanup.test.ts.
#
# smoke_cleanup STATUS LABEL WORK IMAGE...: removes every container and image carrying LABEL, the named images and the
# temporary directory WORK, then takes a final inventory. It reports only what that inventory confirms, and exits non-zero
# when cleanup cannot be confirmed: a removal that failed, an inventory that could not be taken, or anything left over.
# A run whose checks all passed (STATUS 0) but whose cleanup is unconfirmed exits 1; a run that already failed keeps its
# own non-zero STATUS.
smoke_cleanup() {
  local status="$1" label="$2" work="$3"
  shift 3
  local images=("$@") problems=() ids

  if ids="$(docker ps -aq --filter "label=$label")"; then
    if [[ -n "$ids" ]]; then
      # shellcheck disable=SC2086 # one id per word
      docker rm -f $ids > /dev/null || problems+=("removing containers failed")
    fi
  else
    problems+=("listing containers failed")
  fi

  local image
  for image in "${images[@]}"; do
    if ids="$(docker image ls -q "$image")"; then
      [[ -z "$ids" ]] || docker image rm -f "$image" > /dev/null || problems+=("removing image $image failed")
    else
      problems+=("listing image $image failed")
    fi
  done
  if ids="$(docker image ls -q --filter "label=$label")"; then
    # shellcheck disable=SC2086
    [[ -z "$ids" ]] || docker image rm -f $ids > /dev/null || problems+=("removing labeled images failed")
  else
    problems+=("listing labeled images failed")
  fi

  [[ -z "$work" ]] || rm -rf "$work" || problems+=("removing the temporary directory failed")

  # The final inventory, independent of what the removals reported.
  local containers_left images_left
  if containers_left="$(docker ps -aq --filter "label=$label")"; then
    [[ -z "$containers_left" ]] || problems+=("containers left: ${containers_left//$'\n'/ }")
  else
    problems+=("the final container inventory could not be taken")
  fi
  if images_left="$(docker image ls -q --filter "label=$label")"; then
    [[ -z "$images_left" ]] || problems+=("labeled images left: ${images_left//$'\n'/ }")
  else
    problems+=("the final image inventory could not be taken")
  fi
  for image in "${images[@]}"; do
    if ids="$(docker image ls -q "$image")"; then
      [[ -z "$ids" ]] || problems+=("image left: $image")
    else
      problems+=("the final inventory of image $image could not be taken")
    fi
  done
  [[ -z "$work" || ! -e "$work" ]] || problems+=("temporary directory left: $work")

  if ((${#problems[@]} == 0)); then
    echo "cleanup: confirmed: no containers or images with label $label, images ${images[*]} absent, temporary directory removed"
    return "$status"
  fi
  local problem
  for problem in "${problems[@]}"; do echo "CLEANUP NOT CONFIRMED: $problem" >&2; done
  ((status != 0)) || status=1
  return "$status"
}
