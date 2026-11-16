#!/usr/bin/env sh
# Prepare the audit anchor directory (bind mount of audit_anchor, outside the
# database volume): 700 for the host user plus rwx for uid 10002 through an
# ACL; never 777. The anchor files inside are 0644, so the host user can read
# them while the directory keeps everyone else out.
#   scripts/anchor_dir.sh [--strict] DIR
# Used by init_secrets.sh and, before the retire, by make reset/fclean (З-9):
# a directory Docker creates itself for the bind mount belongs to root and
# audit_anchor (uid 10002) could never write to it.
# --strict: exit 1 instead of a warning when uid 10002 cannot get write access.
set -eu
AUDIT_UID=10002
strict=no
if [ "${1:-}" = --strict ]; then strict=yes; shift; fi
anchor_dir="${1:?usage: anchor_dir.sh [--strict] DIR}"

if [ ! -d "$anchor_dir" ]; then
  mkdir -p "$anchor_dir"
  chmod 700 "$anchor_dir"
  echo "created $anchor_dir (audit anchors and chain registry; keep it, do not git clean it)"
fi
if [ -O "$anchor_dir" ]; then
  chmod 700 "$anchor_dir"
  if command -v setfacl >/dev/null 2>&1 && setfacl -m "u:$AUDIT_UID:rwx" "$anchor_dir" 2>/dev/null; then
    :
  elif [ "$(id -u)" = 0 ]; then
    chown "$AUDIT_UID:$AUDIT_UID" "$anchor_dir"
  else
    echo "warning $anchor_dir: cannot grant write access to audit_anchor (uid $AUDIT_UID)." >&2
    echo "        No anchors will be written and audit_anchor stays unhealthy. Install the acl package and rerun," >&2
    echo "        or: sudo setfacl -m u:$AUDIT_UID:rwx $anchor_dir" >&2
    [ "$strict" = no ] || exit 1
  fi
else
  echo "note    $anchor_dir is not owned by you; permissions left as they are"
fi
