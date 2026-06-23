use anyhow::{Context as _, Result};
use pcsc::{Card, Context, Protocols, Scope, ShareMode};

use crate::smartcard::apdu::format_hex;

pub fn connect_first_card() -> Result<Card> {
    let context = Context::establish(Scope::User).context("failed to initialize PC/SC")?;

    let mut readers_buffer = [0_u8; 2048];

    let readers: Vec<_> = context
        .list_readers(&mut readers_buffer)
        .context("failed to list smart-card readers")?
        .collect();

    if readers.is_empty() {
        anyhow::bail!("no smart-card readers found");
    }

    for reader in &readers {
        println!("Reader: {}", reader.to_string_lossy());
    }

    let reader = readers[0];

    let card = context
        .connect(reader, ShareMode::Shared, Protocols::ANY)
        .context("reader found, but no smart card is available")?;

    let status = card
        .status2_owned()
        .context("failed to read smart-card status")?;

    for reader_name in status.reader_names() {
        println!("Connected reader: {}", reader_name.to_string_lossy());
    }

    println!("Protocol: {:?}", status.protocol2());
    println!("ATR: {}", format_hex(status.atr()));

    Ok(card)
}
