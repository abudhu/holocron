#!/usr/bin/env bash
# check-buildspec-atsigns.sh — guard against the OneDev buildspec parser
# rejecting `.onedev-buildspec.yml` on an unpaired at-sign.
#
# OneDev treats `@var@` as variable interpolation in CommandStep `commands:`
# blocks. A bare at-sign (e.g. bash `$@`, `${arr[@]}`, an email address in a
# comment INSIDE a commands: block, etc.) makes the spec invalid and silently
# kills BranchUpdateTrigger.
#
# WHAT THIS SCRIPT DOES:
#   1. Skips top-level YAML comment lines (start with `##` or `#` at indent 0)
#      — those are stripped by YAML parse before OneDev's validator runs.
#   2. Flags any remaining line containing `@`.
#   3. Exits 1 if any flagged lines are found. Set
#      HOLOCRON_BUILDSPEC_ATSIGNS_OK=1 to override after manual review.
#
# Exit codes:
#   0 — no risky at-signs found (or override set)
#   1 — at-signs detected inside YAML content; spec may not validate
#   2 — file not found
#
# Wire into a pre-commit hook to catch this before push:
#   #!/bin/sh
#   ./scripts/check-buildspec-atsigns.sh || exit 1

set -euo pipefail

FILE="${1:-.onedev-buildspec.yml}"

if [ ! -f "$FILE" ]; then
  echo "error: $FILE not found" >&2
  exit 2
fi

# Strip top-level YAML comments (lines starting with optional whitespace
# then `#`), then search for at-signs in what remains. This catches
# at-signs in YAML keys, values, and inside `commands:` strings — which
# IS where OneDev scans — while ignoring documentation comments.
#
# Note: bash comments inside `commands:` literal scalars still get
# scanned by us (and by OneDev), which is the right call: a `# uses $@`
# bash comment inside commands: WILL invalidate the spec.
MATCHES=$(
  awk '
    # Skip YAML comments at any indent level. The contents of a
    # `commands: |` literal scalar are NOT comments at the YAML layer
    # even if they start with `#` (they are string content). We
    # approximate by tracking indent: if a line is indented MORE than
    # the most recent `commands:` line we have seen, treat it as
    # commands-block content and scan it.
    {
      # detect commands: block start
      if (match($0, /^[[:space:]]*commands:/)) {
        match($0, /^[[:space:]]*/)
        cmd_indent = RLENGTH
        in_cmd = 1
        next
      }
      # line indent
      match($0, /^[[:space:]]*/)
      line_indent = RLENGTH

      # leave the commands: block when indent drops
      if (in_cmd && length($0) > 0 && line_indent <= cmd_indent) {
        in_cmd = 0
      }

      # inside commands: block — scan everything (including bash # comments)
      if (in_cmd) {
        if (index($0, "@") > 0) {
          print NR ": " $0
        }
        next
      }

      # outside commands: — skip YAML comment lines
      if (match($0, /^[[:space:]]*#/)) {
        next
      }

      # outside commands:, not a comment — scan
      if (index($0, "@") > 0) {
        print NR ": " $0
      }
    }
  ' "$FILE"
)

if [ -z "$MATCHES" ]; then
  echo "OK: no risky at-signs in $FILE"
  exit 0
fi

echo "WARN: at-signs found in $FILE (commands: blocks or YAML content):"
echo ""
echo "$MATCHES" | sed 's/^/  /'
echo ""
echo "OneDev treats @var@ as variable interpolation in CommandStep commands:"
echo "blocks. An unpaired bare @ (e.g. bash \$@ or \${arr[@]}) invalidates the"
echo "spec and silently kills BranchUpdateTrigger. Verify each line above:"
echo "  - Inside @...@ that names a real OneDev variable (@commit_hash@, @server@)? OK."
echo "  - Doubled as @@ for a literal at-sign? OK."
echo "  - Anything else? Refactor (see onedev-ci skill pitfall #11)."
echo ""
echo "After verification, override with HOLOCRON_BUILDSPEC_ATSIGNS_OK=1."

if [ "${HOLOCRON_BUILDSPEC_ATSIGNS_OK:-0}" = "1" ]; then
  echo "OVERRIDE: HOLOCRON_BUILDSPEC_ATSIGNS_OK=1 set, exiting 0."
  exit 0
fi

exit 1
