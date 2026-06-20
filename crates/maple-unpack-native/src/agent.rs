//! The instrumentation agent, embedded into the binary.
//!
//! `resources/agent.js` ports the OEP-finding logic of ergrelet/unlicense (GPL-3.0)
//! `resources/frida.js`, with the host transport changed from Frida's message channel (which the
//! Rust frida binding does not deliver) to a local socket. Attribution lives in the crate NOTICE.

const AGENT_JS: &str = include_str!("resources/agent.js");

/// The agent source with the driver's listening port injected.
pub fn agent_source(port: u16) -> String {
    format!("const DRIVER_PORT = {port};\n{AGENT_JS}")
}
