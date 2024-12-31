# Argon2pp

This is a C++20 wrapper for the Argon2 hash function library, which is written in C, and is available as a [reference implementation](https://github.com/P-H-C/phc-winner-argon2) on GitHub. Argon2pp is a header-only project; `# include "argon2hash.h"`  somewhere in your code will do the trick. You will of course need `libargon2` and the header file `argon2.h` in your compiler's include path. In Debian-like systems this is found in the `libargon2-dev` package. Other distros will have similar packages.

The `argon2hash.cpp` file is a very simple test harness showing how to use the Argon2-id variant of the hash.

The license is BSD-3.
