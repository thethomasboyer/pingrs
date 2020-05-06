# pingrs

A concurrent implementation of `ping` in Rust.

*WIP (untested, maybe unstable, but Just Works™).*

## Usage

### Linux

`ping.zsh` builds, sets relevant file capabilities (needs `sudo` for that), and runs the `release` version of `pingrs`.

`ping-debug.zsh` does the same, in debug mode.

### macOS

TBD

### Windows

TBD w/ pain

## Known problems

* `pingrs` may need special rights depending on OS.
* **more importantly, current use of `pnet` is weird, as `pingrs` re-implements its own ICMP abstraction, but still makes use of `pnet`'s implementation to send/receive packets.**

## Dependencies

* [`pnet`](https://crates.io/crates/pnet)
* [`rand`](https://crates.io/crates/rand)
* [`internet-checksum`](https://crates.io/crates/internet-checksum)
* [`ctrlc`](https://crates.io/crates/ctrlc)
* [`crossbeam-channel`](https://crates.io/crates/crossbeam-channel)
* [`trust-dns-resolver`](https://crates.io/crates/trust-dns-resolver)
