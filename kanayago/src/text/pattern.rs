///! Pattern generation and offset finding for exploit development
///!
///! This module implements de Bruijn sequence generation for creating
///! unique patterns used in buffer overflow exploit development.

/// Generates a cyclic pattern (de Bruijn sequence) for exploit development.
///
/// The pattern is unique such that any substring of a given length appears
/// only once in the sequence. This is useful for finding offsets in memory
/// during exploit development.
///
/// # Arguments
/// * `length` - The desired length of the pattern
/// * `sets` - Optional custom character sets. If None, uses default sets.
///
/// # Returns
/// A String containing the generated pattern
///
/// # Examples
/// ```
/// use kanayago::text::pattern::create;
///
/// let pattern = create(100, None);
/// assert_eq!(pattern.len(), 100);
/// ```
pub fn create(length: usize, sets: Option<&[&str]>) -> String {
    // Default character sets
    let default_sets = vec!["ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz", "0123456789"];

    let char_sets: Vec<&str> = sets.unwrap_or(&default_sets).to_vec();

    // Convert sets to character vectors
    let mut sets_chars: Vec<Vec<char>> = Vec::new();
    for set in &char_sets {
        sets_chars.push(set.chars().collect());
    }

    let mut pattern = String::new();
    let set_count = sets_chars.len();

    // Generate pattern by cycling through character sets
    let mut indices = vec![0usize; set_count];

    while pattern.len() < length {
        // Build current substring from indices
        for (i, &idx) in indices.iter().enumerate() {
            if pattern.len() >= length {
                break;
            }
            pattern.push(sets_chars[i][idx]);
        }

        // Increment indices (like a multi-base counter)
        let mut carry = true;
        for i in (0..set_count).rev() {
            if carry {
                indices[i] += 1;
                if indices[i] >= sets_chars[i].len() {
                    indices[i] = 0;
                } else {
                    carry = false;
                }
            }
        }

        // If we've cycled through all combinations, break to avoid infinite loop
        if carry && indices.iter().all(|&x| x == 0) && pattern.len() >= set_count {
            // Repeat pattern to fill remaining length
            let current = pattern.clone();
            while pattern.len() < length {
                let remaining = length - pattern.len();
                if remaining >= current.len() {
                    pattern.push_str(&current);
                } else {
                    pattern.push_str(&current[..remaining]);
                }
            }
            break;
        }
    }

    pattern.truncate(length);
    pattern
}

/// Finds the offset of a pattern within a buffer.
///
/// Searches for either a string pattern or a numeric value (interpreted as
/// little-endian bytes) within the generated pattern.
///
/// # Arguments
/// * `length` - The length of the pattern to generate
/// * `query` - The pattern to search for (either string or hex value)
/// * `sets` - Optional custom character sets
///
/// # Returns
/// `Some(offset)` if found, `None` otherwise
///
/// # Examples
/// ```
/// use kanayago::text::pattern;
///
/// let offset = pattern::offset(8192, "Aa3A", None);
/// assert_eq!(offset, Some(9));
/// ```
pub fn offset(length: usize, query: &str, sets: Option<&[&str]>) -> Option<usize> {
    let buffer = create(length, sets);

    // Try direct string search first
    if let Some(pos) = buffer.find(query) {
        return Some(pos);
    }

    // Try interpreting as hex value (little-endian)
    if query.len() >= 8 {
        if let Ok(value) = u64::from_str_radix(query, 16) {
            let bytes = value.to_le_bytes();
            let search_str = String::from_utf8_lossy(&bytes[..4]);
            if let Some(pos) = buffer.find(search_str.as_ref()) {
                return Some(pos);
            }
        }
    }

    // Try as 4-byte hex
    if query.len() == 4 {
        if let Some(pos) = buffer.find(query) {
            return Some(pos);
        }
    }

    None
}

/// Finds the offset of a numeric value (interpreted as little-endian) in the pattern.
///
/// # Arguments
/// * `length` - The length of the pattern to generate
/// * `value` - The numeric value to search for
/// * `sets` - Optional custom character sets
///
/// # Returns
/// `Some(offset)` if found, `None` otherwise
pub fn offset_value(length: usize, value: u32, sets: Option<&[&str]>) -> Option<usize> {
    let buffer = create(length, sets);
    let bytes = value.to_le_bytes();

    // Search for the byte sequence in the buffer
    let buffer_bytes = buffer.as_bytes();
    for i in 0..=buffer_bytes.len().saturating_sub(4) {
        if &buffer_bytes[i..i+4] == &bytes {
            return Some(i);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pattern_create() {
        let pattern = create(50, None);
        assert_eq!(pattern.len(), 50);
        assert!(pattern.starts_with("Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab"));
    }

    #[test]
    fn test_pattern_create_custom_sets() {
        let sets = vec!["ABC", "def", "123"];
        let pattern = create(20, Some(&sets));
        assert_eq!(pattern.len(), 20);
        assert!(pattern.starts_with("Ad1Ad2Ad3Ae1Ae2Ae3"));
    }

    #[test]
    fn test_pattern_offset() {
        let result = offset(8192, "Aa3A", None);
        assert_eq!(result, Some(9));
    }

    #[test]
    fn test_pattern_offset_not_found() {
        let result = offset(100, "ZzZz", None);
        assert_eq!(result, None);
    }

    #[test]
    fn test_pattern_offset_value() {
        // Test finding a 32-bit value
        let pattern = create(8192, None);
        let substring = &pattern[100..104];
        let value = u32::from_le_bytes([
            substring.as_bytes()[0],
            substring.as_bytes()[1],
            substring.as_bytes()[2],
            substring.as_bytes()[3],
        ]);

        let result = offset_value(8192, value, None);
        assert_eq!(result, Some(100));
    }
}
