# forensics

Forensics is a library for helping you deal with bugs in your software. It provides several useful error handling and reporting services.

## Features

- Assertion macros (both fatal and recoverable)
- A customizable error report handler
- The ability to instrument your APIs with error context zones. Use this to assign ownership (or blame) for a block of code.
- Custom key/value attributes that are made available to the report handler.
- A breadcrumb queue to show what actions have been recently taken
- Zero allocations after initialization except for a small allocation for each thread using the context feature. Definitely zero allocations

## Compiling

```bash
$ ./s/setup
$ ./s/build
```

## TODO
- Optionally generate minidump on windows
- Command-line tools for symbolicating a backtrace
- Can we capture the backtrace for *all* threads?
