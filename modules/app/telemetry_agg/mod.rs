#![no_std]

use core::ffi::c_void;

use abi::SyscallTable;
use fluxor_abi as abi;
use fluxor_rt::StepReturn;

include!("../../common/mechanics/stub_body.rs");
