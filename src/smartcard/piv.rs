use anyhow::{Context as _, Result};
use pcsc::Card;

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

const GET_PIV_AUTH_CERT_APDU: &[u8] = &[
    0x00, // CLA
    0xCB, // INS: GET DATA
    0x3F, // P1
    0xFF, // P2
    0x05, // Lc
    0x5C, // Tag list
    0x03, // Object identifier length
    0x5F, 0xC1, 0x05, // PIV Authentication certificate object
    0x00, // Le
];

const TAG_DATA_OBJECT: u32 = 0x53;
const TAG_CERTIFICATE: u32 = 0x70;
const TAG_CERTIFICATE_INFO: u32 = 0x71;

#[derive(Debug)]
pub struct PivCertificate {
    pub encoded_certificate: Vec<u8>,
    pub compressed: bool,
}

pub fn select_piv(card: &Card) -> Result<Vec<u8>> {
    transmit_complete(card, SELECT_PIV_APDU).context("failed to select the PIV application")
}

pub fn read_authentication_certificate(card: &Card) -> Result<PivCertificate> {
    let piv_object = transmit_complete(card, GET_PIV_AUTH_CERT_APDU)
        .context("failed to retrieve the PIV Authentication certificate")?;

    let certificate_container = extract_data_object(&piv_object)?;

    let encoded_certificate = find_tlv(certificate_container, TAG_CERTIFICATE)?
        .context("PIV certificate object did not contain certificate tag 70")?
        .to_vec();

    let certificate_info = find_tlv(certificate_container, TAG_CERTIFICATE_INFO)?
        .and_then(|value| value.first().copied())
        .unwrap_or(0);

    Ok(PivCertificate {
        encoded_certificate,
        compressed: certificate_info & 0x01 != 0,
    })
}

fn extract_data_object(data: &[u8]) -> Result<&[u8]> {
    let tlv = parse_tlv(data)?.context("PIV GET DATA response was empty")?;

    if tlv.tag == TAG_DATA_OBJECT {
        Ok(tlv.value)
    } else {
        // Some cards may return the inner PIV certificate TLVs directly.
        Ok(data)
    }
}
