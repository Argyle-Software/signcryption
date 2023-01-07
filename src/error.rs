
/// Signcryption failure modes
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignCryptError {
  /// Additional Authenticated Data provided to [`crate::sign_before`] and [`crate::verify_before`] 
  /// functions is larger than the allowed maximum of 255 bytes.
  InvalidLength,
  /// The signature was unable to be verified after decryption
  Mismatch,
  /// Error occurred during the encryption phase of [`crate::signcrypt`]
  Encryption,
  /// Error occurred during decryption phase of [`crate::unsigncrypt`]
  Decryption,
  /// The signature is not canonical
  NonCanonicalSig,
  /// Catch-all for other errors
  Generic,
}