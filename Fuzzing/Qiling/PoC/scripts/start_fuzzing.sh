#!/usr/bin/sh

AFL_DEBUG_CHILD_OUTPUT=1 AFL_AUTORESUME=1 AFL_PATH="~/apps/AFLplusplus/" PATH="$AFL_PATH:$PATH" afl-fuzz -i fuzz_setup/in -o fuzz_setup/out -U -- python3 scripts/fuzz.py @@