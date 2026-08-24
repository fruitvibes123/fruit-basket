                                                                                  
  
                                                                          
                                                                                  
                                                                                      
                                                                                      
                        

/// Decode exactly 64 LOWERCASE hex chars to 32 bytes. Anything else — wrong length,
/// non-hex, uppercase — is `None` (fail closed; the seam contract is lowercase).
pub fn decode_hex_32(s: &str) -> Option<[u8; 32]> {
    let b = s.as_bytes();
    if b.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        let hi = hex_nibble(b[2 * i])?;
        let lo = hex_nibble(b[2 * i + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}
