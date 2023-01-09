[![Build Status](https://github.com/Argyle-Software/signcryption/actions/workflows/tests.yml/badge.svg)](https://github.com/Argyle-Software/signcryption/actions)
[![Crates](https://img.shields.io/crates/v/signcryption)](https://crates.io/crates/signcryption)

# Signcryption

Signcryption is a cryptographic technique that combines the functionality of both digital signatures 
and encryption. It allows a sender to both authenticate the origin of a message and protect its 
confidentiality, while also allowing the recipient to verify the authenticity of the message and 
decrypt it without requiring any separate communication channels.

This library implements the [Toorani-Beheshti signcryption](https://arxiv.org/ftp/arxiv/papers/1002/1002.3316.pdf) 
scheme instantiated over Ristretto255 or Ed25519.

## Installation

This library currently depends on the libsodium-sys-stable crate. You will need libsodium installed first. 

https://libsodium.gitbook.io/doc/installation

Or simply use the [`fetch-libsodium`](https://github.com/Argyle-Software/signcryption/blob/5399fd13d0df35c5cdd0774d56c84901a5fe4f69/Cargo.toml#L19) 
feature of this crate on first use which will download and 
install the current stable version.


To add to your project:

```shell
cargo add signcryption
```

or in `Cargo.toml`:

```toml
[dependencies]
signcryption = "0.1"
```

## Usage

The higher level functions complete the full workflow and handle encryption using the AES-GCM crate. 

```rust
// Default uses Ristretto255
let alice_keys = Keypair::default();
let bob_keys = Keypair::default();

let alice_public_key = alice_keys.public.clone();
let bob_public_key = bob_keys.public.clone();

let msg = "Hello".as_bytes();

// Sign and encrypt, returns a SignCrypt struct
let ciphertext = signcrypt(&alice_keys, &bob_public_key, &msg)?;

// Verify and decrypt, returns a plaintext Vec<u8>
let plaintext = unsigncrypt(ciphertext, &alice_public_key, &bob_keys)?;

assert_eq!(payload , &plaintext[..]);
```


To use a different AEAD or for lower level control you'll need to run through the discrete step 
functions themselves. To remove the aes-gcm crate dependency set `default-features = false` in `Cargo.toml`

### Signcrypt

```rust
// Initialise state
let mut state = SignState::default();

// Using Ed25519 keys this time
let alice_keys = Keypair::new(Curve::Ed25519);
let bob_keys = Keypair::new(Curve::Ed25519);

// Shared secret for encryption
let mut crypt_key = [0u8; SHAREDBYTES];

let msg = "Hello".as_bytes()

// Additional Authenticated Data if desired
let sender_id = "alice".as_bytes()
let recipient_id = "bob".as_bytes()
let info = "rust-signcryption".as_bytes()

// Sign plaintext
sign_before(
  &mut state, &mut crypt_key, &SENDER_ID, &RECIPIENT_ID, &INFO, 
  &alice.expose_secret(), &bob.public, msg, Curve::Ed25519
)?;

/////////////////////////////////////////////////////////////
// Encrypt here with your desired AEAD using crypt_key eg. //
// let cipher = ChaCha20Poly1305::new(&crypt_key);         //
/////////////////////////////////////////////////////////////

// Signature to pass to recipient
let mut sig = [0u8; SIGNBYTES];

// Sign ciphertext
sign_after(&mut state, &mut sig, &alice.expose_secret(), &ciphertext, Curve::Ed25519);

// Send ciphertext, signature and correct AAD to recipient
```

### Unsigncrypt
```rust
let mut state = SignState::default();
let mut crypt_key = [0u8; SHAREDBYTES];

// Additional Authenticated Data used to signcrypt the message
let sender_id = "alice".as_bytes()
let recipient_id = "bob".as_bytes()
let info = "rust-signcryption".as_bytes()

// Verify and get shared secret
verify_before(
  &mut state, &mut crypt_key, &sig, &sender_id,
  &recipient_id, &info, &alice_public_key,
  &bob.expose_secret(), Curve::Ed25519
)?; 

////////////////////////////
// Decrypt with crypt_key //
////////////////////////////

// Verify after
verify_after(&mut state, &sig, &alice_public_key, &ciphertext, Curve::Ed25519)?;
```

### Public Verification

Verify the message without learning the decryption key.

```rust
verify_public(
  &sig, &sender_id, &recipient_id, &info, 
  &alice_public_key, &ciphertext, Curve::Ed25519
)?;
```

## Why?

Combining encryption and signing has flaws either way you order them:

*Encrypt then Sign*: An attacker can replace your signature, making it seem as though
they encrypted the file.

*Sign then Encrypt*: The recipient can re-encrypt the file and impersonate you sending the file to someone else.

Signcryption performs signing both before and after the encryption stage, negating these flaws.

## Alternatives

This crate is based on the [Libsodium-Signcryption](https://github.com/jedisct1/libsodium-signcryption) 
library, written in C. 

## Licensing

All crates licensed under either of

 * [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
 * [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in 
the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any 
additional terms or conditions.