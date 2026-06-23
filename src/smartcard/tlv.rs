use anyhow::{Context as _, Result, bail};

#[derive(Debug)]
pub struct Tlv<'a> {
    pub tag: u32,
    pub value: &'a [u8],
    pub total_length: usize,
}

pub fn parse_tlv(data: &[u8]) -> Result<Option<Tlv<'_>>> {
    if data.is_empty() {
        return Ok(None);
    }

    let mut offset = 0;
    let first_tag_byte = data[offset];
    offset += 1;

    let mut tag = u32::from(first_tag_byte);

    if first_tag_byte & 0x1F == 0x1F {
        loop {
            let byte = *data
                .get(offset)
                .context("truncated multi-byte BER-TLV tag")?;

            offset += 1;

            tag = tag.checked_shl(8).context("BER-TLV tag is too large")? | u32::from(byte);

            if byte & 0x80 == 0 {
                break;
            }

            if offset > 4 {
                bail!("BER-TLV tags larger than four bytes are unsupported");
            }
        }
    }

    let first_length_byte = *data.get(offset).context("missing BER-TLV length")?;
    offset += 1;

    let value_length = if first_length_byte & 0x80 == 0 {
        usize::from(first_length_byte)
    } else {
        let length_byte_count = usize::from(first_length_byte & 0x7F);

        if length_byte_count == 0 {
            bail!("indefinite BER-TLV lengths are unsupported");
        }

        if length_byte_count > std::mem::size_of::<usize>() {
            bail!("BER-TLV length is too large for this platform");
        }

        if offset + length_byte_count > data.len() {
            bail!("truncated BER-TLV long-form length");
        }

        let mut length = 0_usize;

        for byte in &data[offset..offset + length_byte_count] {
            length = length
                .checked_mul(256)
                .and_then(|value| value.checked_add(usize::from(*byte)))
                .context("BER-TLV value length overflow")?;
        }

        offset += length_byte_count;
        length
    };

    let value_end = offset
        .checked_add(value_length)
        .context("BER-TLV value length overflow")?;

    if value_end > data.len() {
        bail!(
            "truncated BER-TLV value: declared {} byte(s), only {} available",
            value_length,
            data.len().saturating_sub(offset)
        );
    }

    Ok(Some(Tlv {
        tag,
        value: &data[offset..value_end],
        total_length: value_end,
    }))
}

pub fn find_tlv(data: &[u8], wanted_tag: u32) -> Result<Option<&[u8]>> {
    let mut remaining = data;

    while !remaining.is_empty() {
        let Some(tlv) = parse_tlv(remaining)? else {
            break;
        };

        if tlv.tag == wanted_tag {
            return Ok(Some(tlv.value));
        }

        remaining = &remaining[tlv.total_length..];
    }

    Ok(None)
}
