//!
//!
//!
//!    HOLYNET CLIENT
//!
//!
//!

#[cfg(not(any(
    feature = "udp",
    feature = "ws",
)))]
compile_error!(
    "please enable one of the following transport backends with cargo's --features argument: \
     udp, ws (e.g. --features=udp)"
);


pub mod network;
pub mod runtime;