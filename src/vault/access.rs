use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use password_out::certificate::CertificateKeyProvider;

use super::format::VaultPayload;
use super::service::{
    CertificateVaultSession, load_password_vault, open_certificate_vault_session,
    save_certificate_vault_session, save_password_vault,
};

/// Provides load/save access to a PasswordOut vault.
///
/// Entry operations depend on this interface instead of depending directly on
/// passwords, PFX files, CAC readers, or filesystem encryption details.
pub trait VaultAccess {
    fn load(&mut self, path: &Path) -> Result<VaultPayload, String>;

    fn save(&mut self, path: &Path, payload: &VaultPayload) -> Result<(), String>;
}

/// In-memory implementation used by unit tests.
///
/// It can also simulate load and save failures so command behavior can be
/// tested without real vault files or cryptographic providers.
#[cfg(any(test, feature = "dev-tools"))]
#[derive(Debug, Clone, Default)]
pub struct InMemoryVaultAccess {
    payload: VaultPayload,
    load_count: usize,
    save_count: usize,
    fail_load: Option<String>,
    fail_save: Option<String>,
}

#[cfg(any(test, feature = "dev-tools"))]
impl InMemoryVaultAccess {
    pub fn new(payload: VaultPayload) -> Self {
        Self {
            payload,
            load_count: 0,
            save_count: 0,
            fail_load: None,
            fail_save: None,
        }
    }

    pub fn payload(&self) -> &VaultPayload {
        &self.payload
    }

    pub fn load_count(&self) -> usize {
        self.load_count
    }

    pub fn save_count(&self) -> usize {
        self.save_count
    }

    pub fn fail_next_load(&mut self, message: impl Into<String>) {
        self.fail_load = Some(message.into());
    }

    pub fn fail_next_save(&mut self, message: impl Into<String>) {
        self.fail_save = Some(message.into());
    }
}

#[cfg(any(test, feature = "dev-tools"))]
impl VaultAccess for InMemoryVaultAccess {
    fn load(&mut self, _path: &Path) -> Result<VaultPayload, String> {
        self.load_count += 1;

        if let Some(message) = self.fail_load.take() {
            return Err(message);
        }

        Ok(self.payload.clone())
    }

    fn save(&mut self, _path: &Path, payload: &VaultPayload) -> Result<(), String> {
        self.save_count += 1;

        if let Some(message) = self.fail_save.take() {
            return Err(message);
        }

        self.payload = payload.clone();

        Ok(())
    }
}

/// Password-based production implementation.
pub struct PasswordVaultAccess {
    password: Zeroizing<String>,
}

impl PasswordVaultAccess {
    pub fn new(password: Zeroizing<String>) -> Self {
        Self { password }
    }
}

impl VaultAccess for PasswordVaultAccess {
    fn load(&mut self, path: &Path) -> Result<VaultPayload, String> {
        load_password_vault(path, self.password.as_str())
    }

    fn save(&mut self, path: &Path, payload: &VaultPayload) -> Result<(), String> {
        save_password_vault(path, payload, self.password.as_str())
    }
}

/// Certificate-backed vault access.
///
/// The provider performs the private-key operation. After a successful load,
/// the recovered vault key and original wrappers are retained in a session so
/// subsequent saves preserve the vault's certificate protection.
pub struct CertificateVaultAccess<P>
where
    P: CertificateKeyProvider,
{
    provider: P,
    session: Option<CertificateAccessSession>,
}

struct CertificateAccessSession {
    path: PathBuf,
    vault: CertificateVaultSession,
}

impl<P> CertificateVaultAccess<P>
where
    P: CertificateKeyProvider,
{
    pub fn new(provider: P) -> Self {
        Self {
            provider,
            session: None,
        }
    }

    #[cfg(test)]
    pub fn has_active_session(&self) -> bool {
        self.session.is_some()
    }
}

impl<P> VaultAccess for CertificateVaultAccess<P>
where
    P: CertificateKeyProvider,
{
    fn load(&mut self, path: &Path) -> Result<VaultPayload, String> {
        let (payload, vault) = open_certificate_vault_session(path, &mut self.provider)?;

        self.session = Some(CertificateAccessSession {
            path: path.to_path_buf(),
            vault,
        });

        Ok(payload)
    }

    fn save(&mut self, path: &Path, payload: &VaultPayload) -> Result<(), String> {
        let session = self
            .session
            .as_ref()
            .ok_or_else(|| "certificate vault must be loaded before it can be saved".to_string())?;

        if session.path != path {
            return Err(format!(
                "certificate session was opened for '{}' but save requested '{}'",
                session.path.display(),
                path.display()
            ));
        }

        save_certificate_vault_session(path, payload, &session.vault)
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{CertificateVaultAccess, InMemoryVaultAccess, VaultAccess};
    use crate::vault::format::{VaultEntry, VaultPayload};

    fn test_payload() -> VaultPayload {
        VaultPayload {
            settings: Default::default(),
            entries: vec![VaultEntry {
                id: uuid::Uuid::new_v4(),
                domain: "domain".to_string(),
                username: "GitHub".to_string(),
                hotkey: "CTRL+ALT+G".to_string(),
                secret: "test-secret".to_string(),
                expires_on: None,
            }],
        }
    }

    #[test]
    fn in_memory_access_loads_payload() {
        let mut access = InMemoryVaultAccess::new(test_payload());

        let loaded = access
            .load(Path::new("unused-vault.json"))
            .expect("in-memory vault should load");

        assert_eq!(loaded.entries.len(), 1);
        assert_eq!(loaded.entries[0].username, "GitHub");
        assert_eq!(access.load_count(), 1);
        assert_eq!(access.save_count(), 0);
    }

    #[test]
    fn in_memory_access_saves_payload() {
        let mut access = InMemoryVaultAccess::default();

        let payload = test_payload();

        access
            .save(Path::new("unused-vault.json"), &payload)
            .expect("in-memory vault should save");

        assert_eq!(access.payload(), &payload);
        assert_eq!(access.load_count(), 0);
        assert_eq!(access.save_count(), 1);
    }

    #[test]
    fn in_memory_access_can_fail_next_load() {
        let mut access = InMemoryVaultAccess::default();

        access.fail_next_load("simulated load failure");

        let error = access
            .load(Path::new("unused-vault.json"))
            .expect_err("load should fail");

        assert_eq!(error, "simulated load failure");
        assert_eq!(access.load_count(), 1);

        access
            .load(Path::new("unused-vault.json"))
            .expect("only the next load should fail");
    }

    #[test]
    fn in_memory_access_can_fail_next_save() {
        let mut access = InMemoryVaultAccess::default();

        access.fail_next_save("simulated save failure");

        let error = access
            .save(Path::new("unused-vault.json"), &test_payload())
            .expect_err("save should fail");

        assert_eq!(error, "simulated save failure");
        assert_eq!(access.save_count(), 1);
        assert!(access.payload().entries.is_empty());

        access
            .save(Path::new("unused-vault.json"), &test_payload())
            .expect("only the next save should fail");
    }

    #[test]
    fn certificate_access_loads_modifies_saves_and_reopens_pfx_vault() {
        use password_out::certificate::{
            PfxKeyProvider, SelfSignedCertificateOptions, create_self_signed_pfx, load_pfx_der,
        };

        use crate::vault::entry_ops::add_entry_with_access;
        use crate::vault::format::CertificateBackend;
        use crate::vault::service::{initialize_certificate_vault, load_certificate_vault};

        let test_dir = std::env::temp_dir().join(format!(
            "password-out-certificate-access-test-{}",
            uuid::Uuid::new_v4()
        ));

        std::fs::create_dir_all(&test_dir).expect("test directory should be created");

        let vault_path = test_dir.join("vault.json");

        let generated = create_self_signed_pfx(
            &SelfSignedCertificateOptions {
                common_name: "PasswordOut Access Test".to_string(),
                friendly_name: "PasswordOut Access Test".to_string(),
                rsa_bits: 2048,
                validity_days: 30,
            },
            "pfx-password",
        )
        .expect("PFX generation should succeed");

        let loaded = load_pfx_der(&generated.pfx_der, "pfx-password").expect("PFX should load");

        let provider = PfxKeyProvider::from_loaded_pfx(loaded).expect("provider should be created");

        initialize_certificate_vault(
            &vault_path,
            "backup-password",
            &provider,
            CertificateBackend::Pfx {
                suggested_filename: Some("test.pfx".to_string()),
            },
        )
        .expect("certificate vault should initialize");

        let loaded = load_pfx_der(&generated.pfx_der, "pfx-password").expect("PFX should reload");

        let provider =
            PfxKeyProvider::from_loaded_pfx(loaded).expect("provider should be recreated");

        let mut access = CertificateVaultAccess::new(provider);

        add_entry_with_access(
            &vault_path,
            &mut access,
            "domain".to_string(),
            "GitHub".to_string(),
            "CTRL+ALT+G".to_string(),
            "github-secret".to_string(),
            Some("2026-08-15".to_string()),
        )
        .expect("entry should save through certificate access");

        assert!(access.has_active_session());

        let loaded = load_pfx_der(&generated.pfx_der, "pfx-password")
            .expect("PFX should reload for verification");

        let mut provider = PfxKeyProvider::from_loaded_pfx(loaded)
            .expect("verification provider should be created");

        let payload = load_certificate_vault(&vault_path, &mut provider)
            .expect("saved certificate vault should reopen");

        assert_eq!(payload.entries.len(), 1);
        assert_eq!(payload.entries[0].username, "GitHub");
        assert_eq!(payload.entries[0].domain, "domain");
        assert_eq!(payload.entries[0].hotkey, "CTRL+ALT+G");
        assert_eq!(payload.entries[0].secret, "github-secret");
        assert_eq!(payload.entries[0].expires_on.as_deref(), Some("2026-08-15"));
        assert!(!payload.entries[0].id.is_nil());

        let _ = std::fs::remove_dir_all(test_dir);
    }
}
