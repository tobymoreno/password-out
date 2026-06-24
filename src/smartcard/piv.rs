use anyhow::{Context as _, Result, bail};
use pcsc::Card;
use zeroize::Zeroize;

use crate::smartcard::{
    apdu::transmit_complete,
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
