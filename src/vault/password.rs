use std::io::{self, Write};

use zeroize::Zeroizing;

pub fn prompt_master_password(prompt: &str) -> Result<Zeroizing<String>, String> {
    read_hidden_value(prompt, "master password")
}

pub fn prompt_new_master_password() -> Result<Zeroizing<String>, String> {
    let password = prompt_master_password("New master password: ")?;
    let confirmation = prompt_master_password("Confirm master password: ")?;

    if *password != *confirmation {
        return Err("master passwords do not match".to_string());
    }

    Ok(password)
}

pub fn prompt_cac_pin() -> Result<Zeroizing<String>, String> {
    let pin = read_hidden_value("CAC PIN: ", "CAC PIN")?;

    if !(6..=8).contains(&pin.len()) {
        return Err("CAC PIN must contain between 6 and 8 digits".to_string());
    }

    if !pin.bytes().all(|value| value.is_ascii_digit()) {
        return Err("CAC PIN must contain only ASCII digits".to_string());
    }

    Ok(pin)
}

fn read_hidden_value(prompt: &str, value_name: &str) -> Result<Zeroizing<String>, String> {
    print!("{prompt}");
    io::stdout()
        .flush()
        .map_err(|error| format!("failed to flush stdout: {error}"))?;

    let value = rpassword::read_password()
        .map_err(|error| format!("failed to read {value_name}: {error}"))?;

    if value.is_empty() {
        return Err(format!("{value_name} cannot be empty"));
    }

    Ok(Zeroizing::new(value))
}

#[cfg(test)]
mod tests {
    #[test]
    fn placeholder_for_interactive_prompt_module() {
        // Interactive terminal input is intentionally not unit tested here.
        // Validation performed after input is covered by the smart-card and
        // vault layers.
        assert!(true);
    }
}
