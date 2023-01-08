use crate::*;
use libsodium_sys::crypto_generichash_state as HashState;
use zeroize::Zeroize;

///  Used to hold intermediate values during the signcryption process.
///  
/// It is passed between both the before and after functions.
/// 
/// # Example 
/// ```
/// # use signcryption::*;
/// // Initialise
/// let state = SignState::default();
/// ```
#[repr(align(64))]
pub struct SignState {
  pub h: HashState,
  pub nonce: [u8; SCALARBYTES],
  pub r: [u8; BYTES],
  pub challenge: [u8; CHALLENGEBYTES]
}

impl Default for SignState {
  fn default() -> Self {
    Self { 
      h: HashState { opaque: [0u8; 384] },
      nonce: [0u8; SCALARBYTES],
      r: [0u8; BYTES],
      challenge: [0u8; CHALLENGEBYTES] 
    }
  }
}

// HashState can't derive ZeroizeOnDrop
impl Drop for SignState {
  fn drop(&mut self) {
    self.h.opaque.zeroize();
    self.nonce.zeroize();
    self.r.zeroize();
    self.challenge.zeroize();
  }
}
 