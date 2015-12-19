# rust-multiaddr

A [multiaddr](https://github.com/jbenet/multiaddr) implementation in Rust.

## Usage

```rust
extern crate rust_multiaddr;

use rust_multiaddr::Multiaddr;

fn main() {
    let ma = Multiaddr::from_str("/ip4/1.2.3.4/tcp/567").unwrap();

    // prints [4, 1, 2, 3, 4, 6, 2, 55]
    // (IP4 = 4, TCP = 6, see the multiaddr spec for more information)
    println!("{:?}", ma.as_bytes());
}
```
