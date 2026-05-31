//! Minimal RFC 4648 base32 (lowercase, no padding) — used for the QR/URI form
//! of a chat descriptor. Lowercase base32 matches the onion-address alphabet
//! and is case-insensitive and QR-friendly.

const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

pub fn encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(5) * 8);
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for &b in data {
        buffer = (buffer << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((buffer >> bits) & 0x1f) as usize;
            out.push(ALPHABET[idx] as char);
        }
    }
    if bits > 0 {
        let idx = ((buffer << (5 - bits)) & 0x1f) as usize;
        out.push(ALPHABET[idx] as char);
    }
    out
}

pub fn decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for c in s.chars() {
        let v = match c {
            'a'..='z' => c as u32 - 'a' as u32,
            'A'..='Z' => c as u32 - 'A' as u32,
            '2'..='7' => c as u32 - '2' as u32 + 26,
            _ => return None,
        };
        buffer = (buffer << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_arbitrary() {
        for len in 0..40usize {
            let data: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
            let enc = encode(&data);
            assert!(enc
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
            assert_eq!(decode(&enc).unwrap(), data, "len={len}");
        }
    }

    #[test]
    fn decode_is_case_insensitive() {
        let data = b"talkrypt";
        let enc = encode(data);
        assert_eq!(decode(&enc.to_uppercase()).unwrap(), data);
    }

    #[test]
    fn rejects_invalid_chars() {
        assert!(decode("abc!def").is_none());
        assert!(decode("01890").is_none()); // 0,1,8,9 not in base32
    }
}
