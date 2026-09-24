//! Shared, board-independent building blocks used by the embedded firmware targets.
//!
//! Board applications keep HAL setup and bootloader-specific details locally, while this crate
//! owns portable configuration, storage, CLI/Telnet behavior, network services, and tunnel setup.

#![no_std]
#![allow(async_fn_in_trait)]

pub mod board;
pub mod cli;
pub mod configuration;
pub mod firmware;
pub mod net;
pub mod shell;
pub mod storage;
pub mod telnet;
pub mod tunnel;
