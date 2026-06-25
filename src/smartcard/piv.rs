use anyhow::{Context as _, Result, bail};
use pcsc::Card;
use zeroize::Zeroize;

use crate::smartcard::{
    apdu::{transmit_chained, transmit_complete},
    tlv::{find_tlv, parse_tlv},
};

const SELECT_PIV_APDU: &[u8] = &[
    0x00, // CLA
    0xA4, // INS: SELECT
    0x04, // P1: select by AID
    0x00, // P2
    0x0B, // Lc
    0xA0, 0x00, 0x00, 0x03, 0x08, // NIST RID
    0x00, 0x00, 0x10, 0x00, 0x01, 0x00, // PIV PIX
    0x00, // Le
];

const TAG_DATA_OBJECT: u32 = 0x53;
const TAG_CERTIFICATE: u32 = 0x70;
const TAG_CERTIFICATE_INFO: u32 = 0x71;

const PIV_APPLICATION_PIN_REFERENCE: u8 = 0x80;
const PIV_PIN_LENGTH: usize = 8;
const PIV_PIN_PADDING: u8 = 0xFF;
const APDU_RESPONSE_BUFFER_SIZE: usize = 258;

const GENERAL_AUTHENTICATE_INS: u8 = 0x87;
const RSA_2048_ALGORITHM_REFERENCE: u8 = 0x07;

const TAG_DYNAMIC_AUTHENTICATION_TEMPLATE: u32 = 0x7C;
const TAG_CHALLENGE: u32 = 0x81;
const TAG_RESPONSE: u32 = 0x82;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PivSlot {
    Authentication,
    DigitalSignature,
    KeyManagement,
    CardAuthentication,
}

impl PivSlot {
    pub const ALL: [Self; 4] = [
        Self::Authentication,
        Self::DigitalSignature,
        Self::KeyManagement,
        Self::CardAuthentication,
    ];

    pub fn key_reference(self) -> u8 {
        match self {
            Self::Authentication => 0x9A,
            Self::DigitalSignature => 0x9C,
            Self::KeyManagement => 0x9D,
            Self::CardAuthentication => 0x9E,
        }
    }

    pub fn certificate_object(self) -> [u8; 3] {
        match self {
            Self::Authentication => [0x5F, 0xC1, 0x05],
            Self::DigitalSignature => [0x5F, 0xC1, 0x0A],
            Self::KeyManagement => [0x5F, 0xC1, 0x0B],
            Self::CardAuthentication => [0x5F, 0xC1, 0x01],
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Authentication => "PIV Authentication",
            Self::DigitalSignature => "Digital Signature",
            Self::KeyManagement => "Key Management",
            Self::CardAuthentication => "Card Authentication",
        }
    }
}

#[derive(Debug)]
pub struct PivCertificate {
    pub slot: PivSlot,
    pub encoded_certificate: Vec<u8>,
    pub compressed: bool,
}

pub fn select_piv(card: &Card) -> Result<Vec<u8>> {
    transmit_complete(card, SELECT_PIV_APDU).context("failed to select the PIV application")
}

pub fn verify_pin(card: &Card, pin: &str) -> Result<()> {
    validate_pin(pin)?;

    let mut padded_pin = [PIV_PIN_PADDING; PIV_PIN_LENGTH];
    padded_pin[..pin.len()].copy_from_slice(pin.as_bytes());

    let mut command = Vec::with_capacity(5 + PIV_PIN_LENGTH);
    command.extend_from_slice(&[
        0x00,                          // CLA
        0x20,                          // INS: VERIFY
        0x00,                          // P1
        PIV_APPLICATION_PIN_REFERENCE, // P2
        PIV_PIN_LENGTH as u8,          // Lc
    ]);
    command.extend_from_slice(&padded_pin);

    let mut response_buffer = [0u8; APDU_RESPONSE_BUFFER_SIZE];

    let response = card
        .transmit(&command, &mut response_buffer)
        .context("failed to transmit PIV PIN verification command");

    padded_pin.zeroize();
    command.zeroize();

    let response = response?;

    if response.len() < 2 {
        bail!(
            "PIV PIN verification returned an invalid {}-byte response",
            response.len()
        );
    }

    let status_offset = response.len() - 2;
    let sw1 = response[status_offset];
    let sw2 = response[status_offset + 1];

    match (sw1, sw2) {
        (0x90, 0x00) => Ok(()),

        (0x63, value) if value & 0xF0 == 0xC0 => {
            let retries = value & 0x0F;

            bail!("incorrect CAC PIN; the card reports {retries} attempt(s) remaining")
        }

        (0x69, 0x83) => {
            bail!("CAC PIN is blocked; do not attempt additional PIN verification")
        }

        (0x6A, 0x80) => {
            bail!("CAC rejected the PIN format without verifying it")
        }

        (0x6A, 0x81) => {
            bail!("CAC PIN verification is not supported over this card interface")
        }

        _ => {
            bail!(
                "CAC PIN verification failed with status {:02X}{:02X}",
                sw1,
                sw2
            )
        }
    }
}

fn validate_pin(pin: &str) -> Result<()> {
    if !(6..=8).contains(&pin.len()) {
        bail!("CAC PIN must contain between 6 and 8 digits");
    }

    if !pin.bytes().all(|value| value.is_ascii_digit()) {
        bail!("CAC PIN must contain only ASCII digits");
    }

    Ok(())
}

/// Performs the RSA private-key primitive with a PIV key-management key.
///
/// The caller must verify the cardholder PIN before calling this function.
///
/// For RSA key transport, the PIV card returns the PKCS#1 encoded message
/// produced by the RSA private-key operation. Padding removal is performed by
/// the caller because the card does not return the final plaintext directly.
pub fn rsa_key_transport(card: &Card, slot: PivSlot, ciphertext: &[u8]) -> Result<Vec<u8>> {
    if slot != PivSlot::KeyManagement {
        bail!(
            "RSA key transport requires the PIV key-management slot; received {:02X}",
            slot.key_reference()
        );
    }

    if ciphertext.len() != 256 {
        bail!(
            "RSA-2048 ciphertext must contain exactly 256 bytes; received {}",
            ciphertext.len()
        );
    }

    let mut inner = Vec::new();

    // Empty response tag requests the result of the operation.
    append_tlv(&mut inner, TAG_RESPONSE, &[])?;

    // For RSA transport, the encrypted key is supplied as challenge tag 81.
    append_tlv(&mut inner, TAG_CHALLENGE, ciphertext)?;

    let mut request = Vec::new();
    append_tlv(&mut request, TAG_DYNAMIC_AUTHENTICATION_TEMPLATE, &inner)?;

    let response = transmit_chained(
        card,
        0x00,
        GENERAL_AUTHENTICATE_INS,
        RSA_2048_ALGORITHM_REFERENCE,
        slot.key_reference(),
        &request,
    )
    .context("PIV RSA key-transport operation failed")?;

    let outer = parse_tlv(&response)?.context("PIV GENERAL AUTHENTICATE response was empty")?;

    if outer.tag != TAG_DYNAMIC_AUTHENTICATION_TEMPLATE {
        bail!(
            "PIV GENERAL AUTHENTICATE returned tag {:X}; expected 7C",
            outer.tag
        );
    }

    if outer.total_length != response.len() {
        bail!(
            "{} trailing byte(s) followed the PIV authentication template",
            response.len() - outer.total_length
        );
    }

    let encoded_message = find_tlv(outer.value, TAG_RESPONSE)?
        .context("PIV GENERAL AUTHENTICATE response did not contain tag 82")?;

    if encoded_message.len() != 256 {
        bail!(
            "PIV RSA operation returned {} bytes; expected 256",
            encoded_message.len()
        );
    }

    Ok(encoded_message.to_vec())
}

fn append_tlv(output: &mut Vec<u8>, tag: u32, value: &[u8]) -> Result<()> {
    encode_tag(output, tag)?;
    encode_length(output, value.len())?;
    output.extend_from_slice(value);
    Ok(())
}

fn encode_tag(output: &mut Vec<u8>, tag: u32) -> Result<()> {
    match tag {
        0x00..=0xFF => {
            output.push(tag as u8);
        }

        0x0100..=0xFFFF => {
            output.extend_from_slice(&(tag as u16).to_be_bytes());
        }

        0x0001_0000..=0x00FF_FFFF => {
            output.push((tag >> 16) as u8);
            output.push((tag >> 8) as u8);
            output.push(tag as u8);
        }

        _ => {
            bail!("BER-TLV tag {tag:X} is too large");
        }
    }

    Ok(())
}

fn encode_length(output: &mut Vec<u8>, length: usize) -> Result<()> {
    if length < 0x80 {
        output.push(length as u8);
        return Ok(());
    }

    if length <= 0xFF {
        output.extend_from_slice(&[0x81, length as u8]);
        return Ok(());
    }

    if length <= 0xFFFF {
        output.push(0x82);
        output.extend_from_slice(&(length as u16).to_be_bytes());
        return Ok(());
    }

    bail!("BER-TLV value length {length} is too large")
}

pub fn read_certificate(card: &Card, slot: PivSlot) -> Result<PivCertificate> {
    let object_id = slot.certificate_object();
    let get_data_apdu = build_get_data_apdu(object_id);

    let piv_object = transmit_complete(card, &get_data_apdu).with_context(|| {
        format!(
            "failed to retrieve {} certificate from slot {:02X}",
            slot.name(),
            slot.key_reference()
        )
    })?;

    let certificate_container = extract_data_object(&piv_object)?;

    let encoded_certificate = find_tlv(certificate_container, TAG_CERTIFICATE)?
        .context("PIV certificate object did not contain certificate tag 70")?
        .to_vec();

    let certificate_info = find_tlv(certificate_container, TAG_CERTIFICATE_INFO)?
        .and_then(|value| value.first().copied())
        .unwrap_or(0);

    Ok(PivCertificate {
        slot,
        encoded_certificate,
        compressed: certificate_info & 0x01 != 0,
    })
}

fn build_get_data_apdu(object_id: [u8; 3]) -> Vec<u8> {
    vec![
        0x00, // CLA
        0xCB, // INS: GET DATA
        0x3F, // P1
        0xFF, // P2
        0x05, // Lc
        0x5C, // Tag list
        0x03, // Object identifier length
        object_id[0],
        object_id[1],
        object_id[2],
        0x00, // Le
    ]
}

fn extract_data_object(data: &[u8]) -> Result<&[u8]> {
    let tlv = parse_tlv(data)?.context("PIV GET DATA response was empty")?;

    if tlv.tag == TAG_DATA_OBJECT {
        Ok(tlv.value)
    } else {
        Ok(data)
    }
}

#[cfg(test)]
mod general_authenticate_tests {
    use super::{append_tlv, encode_length};

    #[test]
    fn encodes_short_form_tlv_length() {
        let mut encoded = Vec::new();

        append_tlv(&mut encoded, 0x82, &[0xAA, 0xBB]).expect("TLV encoding should succeed");

        assert_eq!(encoded, vec![0x82, 0x02, 0xAA, 0xBB]);
    }

    #[test]
    fn encodes_one_byte_long_form_length() {
        let value = vec![0xAA; 128];
        let mut encoded = Vec::new();

        append_tlv(&mut encoded, 0x81, &value).expect("TLV encoding should succeed");

        assert_eq!(&encoded[..3], &[0x81, 0x81, 0x80]);
        assert_eq!(&encoded[3..], value.as_slice());
    }

    #[test]
    fn encodes_two_byte_long_form_length() {
        let value = vec![0xAA; 256];
        let mut encoded = Vec::new();

        append_tlv(&mut encoded, 0x7C, &value).expect("TLV encoding should succeed");

        assert_eq!(&encoded[..4], &[0x7C, 0x82, 0x01, 0x00]);
        assert_eq!(&encoded[4..], value.as_slice());
    }

    #[test]
    fn builds_expected_general_authenticate_template() {
        let ciphertext = vec![0x55; 256];

        let mut inner = Vec::new();
        append_tlv(&mut inner, 0x82, &[]).expect("response TLV should encode");
        append_tlv(&mut inner, 0x81, &ciphertext).expect("challenge TLV should encode");

        let mut outer = Vec::new();
        append_tlv(&mut outer, 0x7C, &inner).expect("authentication template should encode");

        assert_eq!(&outer[..4], &[0x7C, 0x82, 0x01, 0x06]);
        assert_eq!(&outer[4..7], &[0x82, 0x00, 0x81]);
        assert_eq!(&outer[7..10], &[0x82, 0x01, 0x00]);
        assert_eq!(&outer[10..], ciphertext.as_slice());
    }

    #[test]
    fn rejects_unrepresentable_tlv_length() {
        let mut encoded = Vec::new();

        let result = encode_length(&mut encoded, 0x1_0000);

        assert!(result.is_err());
    }
}
