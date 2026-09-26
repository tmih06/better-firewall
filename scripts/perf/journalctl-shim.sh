#!/bin/sh
# journalctl replacement for the attack-lab defender. The slim container has
# no journald, so this emits journald-style JSON records by following the
# sshd log file that `sshd -E` writes. Ignores the journalctl flags
# (--follow --lines=0 --output=json --identifier=...); the protect service
# only needs SYSLOG_IDENTIFIER + MESSAGE per line.
LOG=/var/log/bfw-attack-auth.log
touch "$LOG"
# Historical lines are skipped (--lines=0 semantics): only follow new ones.
tail -n0 -F "$LOG" 2>/dev/null | while IFS= read -r line; do
    case "$line" in
        *"Failed password"*|*"Invalid user"*|*"Bad password"*)
            esc=$(printf '%s' "$line" | sed 's/\\/\\\\/g; s/"/\\"/g')
            printf '{"SYSLOG_IDENTIFIER":"sshd","MESSAGE":"%s"}\n' "$esc"
            ;;
    esac
done
