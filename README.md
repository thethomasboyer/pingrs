# pingrs

A concurrent implementation of `ping` in Rust.

*WIP, unfinished, untested, unstable, but Just Works™.*

## Usage

### Linux

`ping.zsh` builds, sets relevant file capabilities (needs `sudo` for that), and runs the `release` version of `pingrs`. 

`ping-debug.zsh` does the same, in debug mode.

## Known problems

* `pingrs` may need special rights depending on OS.
* panics here and there.
* **more importantly, current use of `pnet` is weird, as `pingrs` re-implements its own ICMP abstraction, but still makes use of `pnet`'s implementation to send/receive packets.**

## Dependencies

* `pnet`
* `rand`
* `internet-checksum`
* `ctrlc`
* `crossbeam-channel`
* `trust-dns-resolver`
