fn main() {
    // Unicorn is linked dynamically (see Cargo.toml), so its bundled GLib shim no longer collides
    // with the GLib in Frida's static devkit; no /FORCE:MULTIPLE symbol merging is needed.
}
