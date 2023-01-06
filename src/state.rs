use crate::*;
use libsodium_sys::crypto_generichash_state as HashState;

///  Used to hold intermediate values during the signcryption process. 
/// It is passed to the various before and after signing functions. 
/// To initialise call [`Default::default()`]
/// 
/// # Example 
/// ```
/// # use signcryption::*;
/// let state = SignState::default();
/// ```
pub struct SignState {
  pub h: HashState,
  pub nonce: [u8; SCALARBYTES],
  pub r: [u8; BYTES],
  pub challenge: [u8; SCALARBYTES]
}

impl Default for SignState {
  fn default() -> Self {
    Self { 
      h: HashState { opaque: [0u8; 384]},
      nonce: [0u8; SCALARBYTES],
      r: [0u8; BYTES],
      challenge: [0u8; CHALLENGEBYTES] 
    }
  }
}

impl Drop for SignState {
  fn drop(&mut self) {
    self.h.opaque.fill(0);
    self.r.fill(0);
  }
}
 