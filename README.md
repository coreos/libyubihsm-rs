libyubihsm-rs [![Build Status](https://travis-ci.org/coreos/libyubihsm-rs.svg?branch=master)](https://travis-ci.org/coreos/libyubihsm-rs)
==========
Rust library for interfacing with the YubiHSM2.

## Requirements
libyubihsm-rs requires the [YubiHSM2 SDK](https://developers.yubico.com/YubiHSM2/Releases/) in order
to build. Once downloaded, `libyubihsm.so.1` \(and a matching `libyubihsm.so` symlink\) should be
placed in the system library directory.

## Usage
Before working with the YubiHSM2, it's recommended to read the [Concepts
page](https://developers.yubico.com/YubiHSM2/Concepts/) in the YubiHSM2 documentation. As explained
there, most of the YubiHSM2's functionality requires the use of a `Session`. `Session`s can be
created through a `Connector`, which connects to a running instance of `yubihsm-connector` \(which
is included in the SDK\). Once a `Session` has been obtained, it can be used for cryptographic
functions provided by the YubiHSM2.

libyubihsm-rs is not currently published on [crates](https://crates.io). It can be added as a
dependency by adding the following to your `Cargo.toml`:
```
[dependencies.libyubihsm]
git = "https://github.com/coreos/libyubihsm-rs"
```

## Documentation
Documentation is not currently hosted anywhere, but can be built by cloning this repository and
running `cargo doc`.
