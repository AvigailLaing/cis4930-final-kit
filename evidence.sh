#!/usr/bin/env bash
# evidence.sh — one command per piece of evidence: screenshot + four-field note, both timestamped.
#
# This is the automation that matters, because the report is 80% of the grade and the usual failure
# is "I did the thing but did not capture it".
#
# Usage:
#   bash evidence.sh "cron persistence" "PD /var/spool/cron/crontabs/ftruman" "aureport -k cron"
#   bash evidence.sh "DA path step 2" "Hospital DC / 4662 events" "bloodyad add dcsync"
#
# Writes:  ~/evidence/EV-<HH-MM-SS>-<slug>.png
#          ~/evidence/notes.md   (appended, four fields, ready to paste into the report)

set -u
WHAT="${1:-}"
WHERE="${2:-unknown}"
TOOL="${3:-unknown}"
DIR="$HOME/evidence"
mkdir -p "$DIR"
STAMP="$(date +%H-%M-%S)"
HUMAN="$(date '+%H:%M')"
SLUG="$(echo "${WHAT:-shot}" | tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9' '-' | cut -c1-40)"
FILE="$DIR/EV-$STAMP-$SLUG.png"

shot() {
  for cmd in "scrot -o" "gnome-screenshot -f" "import -window root" "xfce4-screenshooter -f -s"; do
    bin="${cmd%% *}"
    if command -v "$bin" >/dev/null 2>&1; then
      case "$bin" in
        scrot)                 scrot -o "$FILE" 2>/dev/null ;;
        gnome-screenshot)      gnome-screenshot -f "$FILE" 2>/dev/null ;;
        import)                import -window root "$FILE" 2>/dev/null ;;
        xfce4-screenshooter)   xfce4-screenshooter -f -s "$FILE" >/dev/null 2>&1 ;;
      esac
      [ -s "$FILE" ] && return 0
    fi
  done
  return 1
}

if shot; then
  echo "[OK] screenshot: $FILE"
else
  echo "[!] no screenshot tool worked. Take one manually, then re-run this to log the note."
  echo "    (try: sudo apt-get install -y scrot)"
fi

{
  echo "### ${WHAT:-untitled}"
  echo "- IOC:   ${WHAT:-untitled}"
  echo "- WHERE: $WHERE"
  echo "- TOOL:  $TOOL"
  echo "- TIME:  $HUMAN"
  echo "- SHOT:  $(basename "$FILE")"
  echo
} >> "$DIR/notes.md"

echo "[OK] note appended to $DIR/notes.md"
echo
tail -7 "$DIR/notes.md"
echo
echo "Everything in $DIR is your report material. Copy it off before the pod resets."
