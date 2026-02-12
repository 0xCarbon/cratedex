// Copyright (c) 2025 cratedex contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! # Cratedex: MCP server for Rust documentation indexing, search, and project diagnostics.
//!
//! This library contains the core logic for the Cratedex server.

// Public modules that can be used by the binary entrypoint.
pub mod cli;
pub mod config;
pub mod db;
pub mod engine;
pub mod error;
pub mod error_ext;
pub mod service;
