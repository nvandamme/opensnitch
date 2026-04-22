pub(crate) fn read_ne_bytes_at<const N: usize>(buffer: &[u8], offset: usize) -> Option<[u8; N]> {
    let bytes = buffer.get(offset..offset + N)?;
    bytes.try_into().ok()
}

pub(crate) fn read_ne_value_at<const N: usize, T>(
    buffer: &[u8],
    offset: usize,
    from_ne_bytes: fn([u8; N]) -> T,
) -> Option<T> {
    Some(from_ne_bytes(read_ne_bytes_at(buffer, offset)?))
}
