#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignCryptError {
  InvalidLength,
  Generic,
  Mismatch,
  Encryption,
  Decryption,
  NonCanonicalSignature
}