cargo build --release;
sudo setcap cap_net_raw+ep ./target/release/pingrs;
cargo run --release $1;
