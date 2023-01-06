[![Build Status](https://github.com/Argyle-Software/signcryption/actions/workflows/tests.yml/badge.svg)](https://github.com/Argyle-Software/signcryption/actions)
[![Crates](https://img.shields.io/crates/v/signcryption)](https://crates.io/crates/signcryption)

# Signcryption

Signcryption is a cryptographic technique that combines the functionality of both digital signatures and encryption. It allows a sender to both authenticate the origin of a message and protect its confidentiality, while also allowing the recipient to verify the authenticity of the message and decrypt it without requiring any separate communication channels.

This library implements the [Toorani-Beheshti signcryption](https://arxiv.org/ftp/arxiv/papers/1002/1002.3316.pdf) scheme instantiated over Ristretto255  or Ed25519.

# Installation
Add the following to your `Cargo.toml` file:

```toml
[dependencies]
signcryption = "0.1"
```
# Usage

