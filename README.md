yubihsm-rs
==========
Rust library for interfacing with the YubiHSM2.

## Requirements
yubihsm-rs requires the [YubiHSM2 SDK](https://developers.yubico.com/YubiHSM2/Releases/) in order to
build. Once downloaded, `libyubihsm.so.1` \(and a matching `libyubihsm.so` symlink\) should be
placed in the system library directory, and `yubihsm.h` should be placed in the system include
directory.

## Usage
Before working with the YubiHSM2, it's recommended to read the [Concepts
page](https://developers.yubico.com/YubiHSM2/Concepts/) in the YubiHSM2 documentation. As explained
there, most of the YubiHSM2's functionality requires the use of a `Session`. `Session`s can be
created through a `Connector`, which connects to a running instance of `yubihsm-connector` \(which
is included in the SDK\). Once a `Session` has been obtained, it can be used for cryptographic
functions provided by the YubiHSM2.

yubihsm-rs is not currently published on [crates](https://crates.io). It can be added as a
dependency by adding the following to your `Cargo.toml`:
```
[dependencies.yubihsm]
git = "https://github.com/coreos/yubihsm-rs"
```

## Documentation
Documentation is not currently hosted anywhere, but can be built by cloning this repository and
running `cargo doc`.
