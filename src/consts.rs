/// Length of the public key
pub const PUBLICKEYBYTES: usize = 32;

/// Length of the secret key
pub const SECRETKEYBYTES: usize = 32;

/// Length of the generated shared secret 
pub const SHAREDBYTES: usize = 32;

/// Length of the seed for keypair creation 
pub const SEEDBYTES: usize = 64;

/// Length of the resulting signature
pub const SIGNBYTES: usize = 64;

/// Tag length
pub const MACBYTES: usize = 16;

pub(crate) const NONCEBYTES: usize = 12;
pub(crate) const SCALARBYTES: usize = 32;
pub(crate) const CHALLENGEBYTES: usize = 32;
pub(crate) const BYTES: usize = 32;
pub(crate) const NONREDUCEDSCALARBYTES: usize = 64;
