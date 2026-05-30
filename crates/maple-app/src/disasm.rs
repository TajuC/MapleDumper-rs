//! The `disassemble` command: decode a hex blob with iced-x86 for the inline
//! disassembly view.

#[tauri::command]
pub fn disassemble(hex: String, bits: u32, base: String) -> Vec<String> {
    use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, NasmFormatter};

    let clean: String = hex.chars().filter(char::is_ascii_hexdigit).collect();
    let bytes: Vec<u8> = (0..clean.len() / 2)
        .filter_map(|i| u8::from_str_radix(&clean[i * 2..i * 2 + 2], 16).ok())
        .collect();
    if bytes.is_empty() {
        return Vec::new();
    }
    let bitness = if bits == 32 { 32 } else { 64 };
    let ip = u64::from_str_radix(base.trim_start_matches("0x").trim_start_matches("0X"), 16)
        .unwrap_or(0);
    let mut decoder = Decoder::with_ip(bitness, &bytes, ip, DecoderOptions::NONE);
    let mut formatter = NasmFormatter::new();
    let mut instr = Instruction::default();
    let mut out = Vec::new();
    while decoder.can_decode() {
        let start_pos = decoder.position();
        decoder.decode_out(&mut instr);
        if instr.is_invalid() {
            if decoder.set_position(start_pos + 1).is_err() {
                break;
            }
            decoder.set_ip(ip + (start_pos + 1) as u64);
            continue;
        }
        let mut text = String::new();
        formatter.format(&instr, &mut text);
        out.push(format!("{:08X}  {text}", instr.ip()));
    }
    out
}
