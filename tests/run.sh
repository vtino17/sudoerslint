#!/usr/bin/env bash
# sudoerslint tests. Read-only; fixtures in a temp dir.
set -uo pipefail
cd "$(dirname "$0")/.."
SL="python3 sudoerslint.py"
pass=0; fail=0
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT

assert() {   # <desc> <expect> -- <cmd...>
    local desc="$1" expect="$2"; shift 2; [[ "$1" == "--" ]] && shift
    local out; out="$("$@" 2>&1)"
    if grep -qF -- "$expect" <<<"$out"; then printf '  PASS  %s\n' "$desc"; pass=$((pass+1))
    else printf '  FAIL  %s\n        wanted: %s\n        got: %s\n' "$desc" "$expect" "$out"; fail=$((fail+1)); fi
}
refute() {   # <desc> <needle> -- <cmd...>
    local desc="$1" needle="$2"; shift 2; [[ "$1" == "--" ]] && shift
    local out; out="$("$@" 2>&1)"
    if grep -qF -- "$needle" <<<"$out"; then printf '  FAIL  %s (found %s)\n' "$desc" "$needle"; fail=$((fail+1))
    else printf '  PASS  %s\n' "$desc"; pass=$((pass+1)); fi
}
assert_exit() {  # <desc> <code> -- <cmd...>
    local desc="$1" want="$2"; shift 2; [[ "$1" == "--" ]] && shift
    "$@" >/dev/null 2>&1; local rc=$?
    if [[ "$rc" == "$want" ]]; then printf '  PASS  %s\n' "$desc"; pass=$((pass+1))
    else printf '  FAIL  %s (exit %s want %s)\n' "$desc" "$rc" "$want"; fail=$((fail+1)); fi
}

echo "== syntax =="
if python3 -c "import ast; ast.parse(open('sudoerslint.py').read())"; then
    echo "  PASS  sudoerslint.py parses"; pass=$((pass+1))
else echo "  FAIL  syntax"; fail=$((fail+1)); fi

echo "== NOPASSWD ALL =="
printf 'alice ALL=(ALL) NOPASSWD: ALL\n' > "$T/a"
assert "passwordless full sudo is critical" "CRITICAL" -- $SL "$T/a" --no-color
assert_exit "critical exits non-zero" 1 -- $SL "$T/a" --no-color

echo "== shell-escape binaries (GTFOBins) =="
printf 'bob ALL=(ALL) NOPASSWD: /usr/bin/vim\n' > "$T/vim"
assert "NOPASSWD vim is HIGH"    "shell escape"        -- $SL "$T/vim" --no-color
assert "vim high severity"       "HIGH"                -- $SL "$T/vim" --no-color
printf 'carol ALL=(root) /usr/bin/find\n' > "$T/find"
assert "with-password find is MEDIUM" "MEDIUM"         -- $SL "$T/find" --no-color

echo "== unknown binary is not a false positive =="
printf 'frank ALL=(ALL) NOPASSWD: /usr/local/bin/mytool\n' > "$T/ok"
refute "unknown binary not flagged as escape" "shell escape" -- $SL "$T/ok" --no-color
assert_exit "harmless rule exits zero" 0 -- $SL "$T/ok" --no-color

echo "== root's own ALL rule is not flagged =="
printf 'root ALL=(ALL:ALL) ALL\n' > "$T/root"
refute "root ALL not flagged" "unrestricted"          -- $SL "$T/root" --no-color

echo "== Defaults and env =="
printf 'Defaults !authenticate\n' > "$T/auth"
assert "!authenticate flagged"   "disables the sudo password" -- $SL "$T/auth" --no-color
printf 'Defaults env_keep += "LD_PRELOAD FOO"\n' > "$T/env"
assert "LD_PRELOAD in env_keep"  "LD_PRELOAD"          -- $SL "$T/env" --no-color
printf 'Defaults env_keep += "FOO BAR"\n' > "$T/env2"
refute "harmless env_keep is quiet" "dangerous variable" -- $SL "$T/env2" --no-color

echo "== wildcard and alias resolution =="
printf 'dave ALL=(ALL) /bin/cat /var/log/*\n' > "$T/wild"
assert "wildcard flagged"        "wildcard in command" -- $SL "$T/wild" --no-color
printf 'Cmnd_Alias SVCS = /usr/bin/systemctl, /bin/journalctl\neve ALL=(ALL) SVCS\n' > "$T/alias"
assert "alias resolves to systemctl" "systemctl"       -- $SL "$T/alias" --no-color

echo
echo "== $pass passed, $fail failed =="
[[ $fail -eq 0 ]]
