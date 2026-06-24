use zeroize::Zeroizing;

use super::KeyWrapAlgorithm;

/// Supplies an X.509 certificate containing the public key used to wrap a
/// PasswordOut vault key.
pub trait CertificateSource {
    fn certificate_der(&self) -> Result<Vec<u8>, String>;
}

/// Performs a private-key operation to recover a wrapped PasswordOut vault key.
///
/// Software PFX files and hardware-backed CAC/PIV cards implement this trait
/// differently, while the vault service depends only on this interface.
pub trait CertificatePrivateKey {
    fn unwrap_key(
        &mut self,
        algorithm: KeyWrapAlgorithm,
        wrapped_key: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, String>;
}

/// Complete certificate-backed key provider.
///
/// Initialization only requires `CertificateSource`. Unlocking requires both
/// the public certificate and access to the corresponding private key.
pub trait CertificateKeyProvider: CertificateSource + CertificatePrivateKey {}

impl<T> CertificateKeyProvider for T where T: CertificateSource + CertificatePrivateKey {}
