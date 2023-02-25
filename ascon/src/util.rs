use core::convert::TryInto;

#[inline]
#[allow(clippy::unwrap_used)]
pub fn u8_to_u64(input: &[u8], output: &mut [u64]) {
    for (i, b) in output.iter_mut().enumerate() {
        *b = u64::from_be_bytes(input[(i * 8)..((i + 1) * 8)].try_into().unwrap());
    }
}

#[inline]
pub fn u64_to_u8(input: &[u64], output: &mut [u8]) {
    for (i, &b) in input.iter().enumerate() {
        output[(i * 8)..((i + 1) * 8)].copy_from_slice(&b.to_be_bytes())
    }
}
