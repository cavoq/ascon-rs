#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build -p ascon-ffi --release --locked
# This script uses the default Cargo target directory and Linux linker flags.
"${CC:-cc}" -std=c11 -Wall -Wextra -Werror -Iinclude examples/basic.c \
    target/release/libascon_ffi.a -ldl -lpthread -lm -o target/c-example
./target/c-example
"${CC:-cc}" -std=c11 -Wall -Wextra -Werror -Iinclude tests/c_api.c \
    -Ltarget/release -lascon_ffi -Wl,-rpath,"$PWD/target/release" -o target/c-api-test
./target/c-api-test
"${CXX:-c++}" -x c++ -std=c++11 -Wall -Wextra -Werror -Iinclude \
    examples/basic.c -Ltarget/release -lascon_ffi \
    -Wl,-rpath,"$PWD/target/release" -o target/cpp-example
./target/cpp-example
