#!/usr/bin/env sh
# Demonstrates the CLI on a range of passwords (for documentation / screenshots).
set -eu
cd "$(dirname "$0")/.."
export PYTHONPATH=src
for pw in 'password' 'Password1!' 'qwerty12345' 'Tr0ub4dor&3' 'Xk9#mQ2$vL7!pR4z' 'N7$vT2#kP9@wQ5!xLm3&Zr8^'; do
  echo "\$ pwstrength --no-color --stdin   # input: $(printf '%s' "$pw" | sed 's/./*/g')"
  printf '%s\n' "$pw" | python3 -m pwstrength --no-color --stdin || true
  echo
done
