//! Device Key Provisioning Tool
//!
//! Generates cryptographically secure pre-shared keys (PSK) and device UUIDs,
//! encodes them into the 63-byte TRPV binary format with IEEE 802.3 CRC32,
//! and writes them to a file for flashing/copying onto the device.
//! Can also append the new device to a server registry file.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
use trillby_net::provisioning::DeviceProvisioning;

fn print_usage() {
    eprintln!(
        "Usage: provision [OPTIONS]\n\
         Options:\n\
         \x20 --out <path>         Path to write device.key binary blob (default: device.key)\n\
         \x20 --registry <path>    Path to server registry file to append (default: none)\n\
         \x20 --server-ip <ip>     Server IPv4 (default: 127.0.0.1)\n\
         \x20 --server-port <port> Server Port (default: 8088)\n\
         \x20 --uuid <hex|string>  Custom 16-byte UUID (default: random)\n\
         \x20 --psk <hex>          Custom 32-byte PSK hex (default: random)\n\
         \x20 --dump <path>        Read and verify an existing device.key file\n"
    );
}

fn parse_hex(s: &str, out: &mut [u8]) -> Result<(), String> {
    let clean = s.trim().trim_start_matches("0x");
    if clean.len() != out.len() * 2 {
        return Err(format!("Expected {} hex characters, got {}", out.len() * 2, clean.len()));
    }
    for i in 0..out.len() {
        out[i] = u8::from_str_radix(&clean[i * 2..i * 2 + 2], 16)
            .map_err(|e| format!("Invalid hex byte at index {}: {}", i, e))?;
    }
    Ok(())
}

fn hex_str(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", b);
    }
    s
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let mut out_path = String::from("device.key");
    let mut registry_path: Option<String> = None;
    let mut server_ip_str = String::from("127.0.0.1");
    let mut server_port: u16 = 8088;
    let mut custom_uuid: Option<String> = None;
    let mut custom_psk: Option<String> = None;
    let mut dump_path: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--out" => {
                i += 1;
                if i < args.len() { out_path = args[i].clone(); }
            }
            "--registry" => {
                i += 1;
                if i < args.len() { registry_path = Some(args[i].clone()); }
            }
            "--server-ip" => {
                i += 1;
                if i < args.len() { server_ip_str = args[i].clone(); }
            }
            "--server-port" => {
                i += 1;
                if i < args.len() { server_port = args[i].parse()?; }
            }
            "--uuid" => {
                i += 1;
                if i < args.len() { custom_uuid = Some(args[i].clone()); }
            }
            "--psk" => {
                i += 1;
                if i < args.len() { custom_psk = Some(args[i].clone()); }
            }
            "--dump" => {
                i += 1;
                if i < args.len() { dump_path = Some(args[i].clone()); }
            }
            "--help" | "-h" => {
                print_usage();
                return Ok(());
            }
            other => {
                eprintln!("Unknown argument: {}", other);
                print_usage();
                std::process::exit(1);
            }
        }
        i += 1;
    }

    if let Some(path) = dump_path {
        println!("==> Reading and verifying provisioning blob: {}", path);
        let mut file = File::open(&path)?;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)?;
        let decoded = DeviceProvisioning::decode(&buf).map_err(|e| format!("{:?}", e))?;
        println!("Status: VALID");
        println!("Device UUID: {}", hex_str(&decoded.device_uuid));
        println!("PSK:         {}", hex_str(&decoded.psk));
        println!(
            "Server:      {}.{}.{}.{}:{}",
            decoded.server_ip[0], decoded.server_ip[1], decoded.server_ip[2], decoded.server_ip[3], decoded.server_port
        );
        return Ok(());
    }

    // Parse server IP
    let ip_parts: Vec<&str> = server_ip_str.split('.').collect();
    if ip_parts.len() != 4 {
        return Err(format!("Invalid IPv4 address: {}", server_ip_str).into());
    }
    let server_ip = [
        ip_parts[0].parse()?,
        ip_parts[1].parse()?,
        ip_parts[2].parse()?,
        ip_parts[3].parse()?,
    ];

    // Generate or parse UUID
    let mut device_uuid = [0u8; 16];
    if let Some(ref u) = custom_uuid {
        if parse_hex(u, &mut device_uuid).is_err() {
            // If not hex, copy as UTF-8 string truncated/padded
            let b = u.as_bytes();
            let copy_len = b.len().min(16);
            device_uuid[..copy_len].copy_from_slice(&b[..copy_len]);
        }
    } else {
        trillby_net::fill_random(&mut device_uuid)
            .map_err(|e| format!("Failed to read random UUID: {}", e))?;
    }

    // Generate or parse PSK
    let mut psk = [0u8; 32];
    if let Some(ref p) = custom_psk {
        parse_hex(p, &mut psk).map_err(|e| format!("Invalid PSK hex: {}", e))?;
    } else {
        trillby_net::fill_random(&mut psk)
            .map_err(|e| format!("Failed to read random PSK: {}", e))?;
    }

    let creds = DeviceProvisioning::new(device_uuid, psk, server_ip, server_port);
    let mut blob = [0u8; DeviceProvisioning::LEN];
    creds.encode(&mut blob);

    // Write device.key binary
    if let Some(parent) = Path::new(&out_path).parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let mut file = File::create(&out_path)?;
    file.write_all(&blob)?;

    println!("============================================================");
    println!(" Trillby Device Provisioning Complete");
    println!(" Output file: {}", out_path);
    println!(" Device UUID: {}", hex_str(&device_uuid));
    println!(" PSK (hex):   {}", hex_str(&psk));
    println!(" Server:      {}:{}", server_ip_str, server_port);
    println!("============================================================");

    // Append to server registry file if specified
    if let Some(reg_path) = registry_path {
        let mut reg_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&reg_path)?;

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        writeln!(
            reg_file,
            "{}\t{}\t{}",
            hex_str(&device_uuid),
            hex_str(&psk),
            timestamp
        )?;
        println!("Appended device to server registry: {}", reg_path);
    }

    Ok(())
}
