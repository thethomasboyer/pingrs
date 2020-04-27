# pingrs
A concurrent implementation of ping in Rust. 

Using `pnet`, `rand`, `internet-checksum`, `ctrlc` and `crossbeam-channel`.

*WIP, unfinished, untested, unstable, panics easily, but Just Works™.*

## Known problems
* pingrs may need special rights depending on OS.
* mdev is not computed.
* panics here and there.
* **more importantly, current use of `pnet` is weird, as `pingrs` re-implements its own ICMP abstraction, but still makes use of `pnet`'s implementation to send/receive packets.**
