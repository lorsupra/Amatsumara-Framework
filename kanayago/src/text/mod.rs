///! Text manipulation utilities for exploit development
///!
///! This module provides various text-related utilities including:
///! - Pattern generation (de Bruijn sequences)
///! - Encoding/decoding
///! - String manipulation
///! - Randomization utilities

pub mod pattern;

// Re-export commonly used functions
pub use pattern::{create as pattern_create, offset as pattern_offset, offset_value as pattern_offset_value};
