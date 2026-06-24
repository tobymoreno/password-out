use anyhow::{Context as _, Result, bail};
use pcsc::Card;

const MAX_EXCHANGES: usize = 128;
const MAX_RESPONSE_SIZE: usize = 1024 * 1024;
const MAX_SHORT_APDU_DATA: usize = 255;
const COMMAND_CHAINING_BIT: u8 = 0x10;

/// Sends an APDU and returns all response data without the final status word.
///
/// Handles:
/// - `9000`: success
/// - `61xx`: additional bytes available through GET RESPONSE
/// - `6Cxx`: incorrect Le; retry using the length supplied by the card
pub fn transmit_complete(card: &Card, apdu: &[u8]) -> Result<Vec<u8>> {
    let mut current_apdu = apdu.to_vec();
    let mut complete_response = Vec::new();

    for _ in 0..MAX_EXCHANGES {
        let response = transmit_once(card, &current_apdu)?;

        if response.len() < 2 {
            bail!(
                "card returned an invalid response containing only {} byte(s)",
                response.len()
            );
        }

        let data_length = response.len() - 2;
        let data = &response[..data_length];
        let sw1 = response[data_length];
        let sw2 = response[data_length + 1];

        if complete_response.len() + data.len() > MAX_RESPONSE_SIZE {
            bail!(
                "card response exceeded the maximum allowed size of {} bytes",
                MAX_RESPONSE_SIZE
            );
        }

        complete_response.extend_from_slice(data);

        match (sw1, sw2) {
            (0x90, 0x00) => return Ok(complete_response),

            (0x61, available_length) => {
                current_apdu = vec![0x00, 0xC0, 0x00, 0x00, available_length];
            }

            (0x6C, correct_length) => {
                let le = current_apdu
                    .last_mut()
                    .context("cannot correct Le on an empty APDU")?;

                *le = correct_length;
            }

            _ => {
                bail!("card command failed with status word {sw1:02X}{sw2:02X}");
            }
        }
    }

    bail!(
        "card response did not complete after {} exchanges",
        MAX_EXCHANGES
    )
}

/// Sends a command whose data field may exceed the 255-byte short-APDU limit.
///
/// All non-final APDUs set the ISO command-chaining bit in CLA and expect an
/// empty `9000` response. The final APDU clears the chaining bit, includes Le,
/// and is completed through `transmit_complete`.
pub fn transmit_chained(
    card: &Card,
    cla: u8,
    ins: u8,
    p1: u8,
    p2: u8,
    data: &[u8],
) -> Result<Vec<u8>> {
    if data.is_empty() {
        let apdu = vec![cla, ins, p1, p2, 0x00];

        return transmit_complete(card, &apdu);
    }

    let chunks: Vec<&[u8]> = data.chunks(MAX_SHORT_APDU_DATA).collect();

    for (index, chunk) in chunks.iter().enumerate() {
        let is_final = index + 1 == chunks.len();

        let command_cla = if is_final {
            cla
        } else {
            cla | COMMAND_CHAINING_BIT
        };

        let mut apdu = Vec::with_capacity(6 + chunk.len());
        apdu.extend_from_slice(&[command_cla, ins, p1, p2, chunk.len() as u8]);
        apdu.extend_from_slice(chunk);

        if is_final {
            apdu.push(0x00);

            return transmit_complete(card, &apdu);
        }

        verify_chained_response(card, &apdu)?;
    }

    bail!("APDU command chaining completed without sending a final command")
}

fn verify_chained_response(card: &Card, apdu: &[u8]) -> Result<()> {
    let response = transmit_once(card, apdu)?;

    if response.len() < 2 {
        bail!(
            "card returned an invalid chained-command response containing only {} byte(s)",
            response.len()
        );
    }

    let status_offset = response.len() - 2;
    let response_data = &response[..status_offset];
    let sw1 = response[status_offset];
    let sw2 = response[status_offset + 1];

    if !response_data.is_empty() {
        bail!(
            "non-final chained command unexpectedly returned {} data byte(s)",
            response_data.len()
        );
    }

    if (sw1, sw2) != (0x90, 0x00) {
        bail!("non-final chained command failed with status word {sw1:02X}{sw2:02X}");
    }

    Ok(())
}

fn transmit_once(card: &Card, apdu: &[u8]) -> Result<Vec<u8>> {
    let mut response_buffer = [0_u8; 4096];

    let response = card
        .transmit(apdu, &mut response_buffer)
        .with_context(|| format!("failed to transmit APDU {}", format_hex(apdu)))?;

    Ok(response.to_vec())
}

pub fn format_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}
