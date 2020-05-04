cargo build;
sudo setcap cap_net_raw+ep ./target/debug/pingrs;
cargo run $1;