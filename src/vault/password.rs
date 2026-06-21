use std::io::{self, Write};

use zeroize::Zeroizing;

pub fn prompt_master_password(prompt: &str) -> Result<Zeroizing<String>, String> {
    print!("{prompt}");
    io::stdout()
        .flush()
        .map_err(|error| format!("failed to flush stdout: {error}"))?;

    let password = rpassword::read_password()
        .map_err(|error| format!("failed to read master password: {error}"))?;

    if password.is_empty() {
        return Err("master password cannot be empty".to_string());
    }

    Ok(Zeroizing::new(password))
}

pub fn prompt_new_master_password() -> Result<Zeroizing<String>, String> {
    let password = prompt_master_password("New master password: ")?;
    let confirmation = prompt_master_password("Confirm master password: ")?;

    if *password != *confirmation {
        return Err("master passwords do not match".to_string());
    }

    Ok(password)
}

#[cfg(test)]
mod tests {
    #[test]
    fn placeholder_for_interactive_prompt_module() {
        // Interactive terminal input is intentionally not unit tested here.
        // The vault crypto and service layers validate empty passwords and
        // incorrect-password behavior independently.
        assert!(true);
    }
}
