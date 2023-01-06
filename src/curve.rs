/// The curve used, variants are Ristretto255 or Edwards25519. Ristretto255 
/// is recommended and the default variant.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum Curve {
  /// Ed25519 is a specific curve that is defined over the prime field GF(p), 
  /// where p is the prime 2^255 - 19. It was designed to be fast and secure, 
  /// and is widely used in various cryptographic protocols.
  /// 
  /// https://ed25519.cr.yp.to/
  Ed25519,
  /// Ristretto255 is a curve isomorphism of Ed25519, which means that it is 
  /// an alternative representation of the same curve. Ristretto255 was designed 
  /// to address some potential vulnerabilities in Ed25519 that could allow an 
  /// attacker to forge signatures or recover private keys. It does this by 
  /// using a different encoding for points on the curve, which makes it more 
  /// difficult for an attacker to carry out these attacks.
  /// 
  /// https://ristretto.group/why_ristretto.html
  Ristretto255
}