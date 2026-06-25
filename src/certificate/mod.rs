mod cac;
mod identity;
mod key_wrap;
mod pfx;
mod provider;
mod self_signed;
mod service;

pub use cac::{CacCertificateSource, CacKeyProvider};
pub use identity::{
    CertificateIdentity, certificate_identity, certificate_identity_from_der,
    verify_certificate_identity,
};
pub use key_wrap::{KeyWrapAlgorithm, wrap_key_with_certificate};
pub use pfx::PfxKeyProvider;
pub use provider::{CertificateKeyProvider, CertificatePrivateKey, CertificateSource};
pub use self_signed::{
    GeneratedCertificate, LoadedPfx, SelfSignedCertificateOptions, create_self_signed_pfx,
    load_pfx, load_pfx_der, write_pfx,
};
pub use service::unwrap_key_with_provider;
