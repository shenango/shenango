## Code Overview

apps - synthetic and benchmarking applications.

base - a extension to the standard C library that provides tools for managing
lists, memory, bitmaps, initialization, atomics, and several other useful
features.

bindings - language bindings (C++ and rust) for the runtime.

dpdk - [DPDK](https://www.dpdk.org/) library for accessing NIC queues
from userspace.

iokernel - dedicated core that steers packets and reallocates cores
across applications.

net - a packet manipulation library.

runtime - a user-level threading and networking runtime.

shim - a shim layer that enables running unmodified
[PARSEC](http://parsec.cs.princeton.edu/) applications atop Shenango.


## Coding Style

Use the following conventions for C code:
https://www.kernel.org/doc/html/v4.10/process/coding-style.html

Use the following conventions for C++ code:
https://google.github.io/styleguide/cppguide.html

For third party libraries and tools, use their existing coding style.

For some helpful tips on how to write clean code, see:
https://www.lysator.liu.se/c/pikestyle.html
