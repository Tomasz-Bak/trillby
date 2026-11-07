//! Zero-allocation Device Provisioning Blob & Loader (#![no_std])
//!
//! Binary layout (63 bytes total):
//! - 0..4:   Magic "TRPV" (4 bytes)
//! - 4..5:   Version 0x01 (1 byte)
//! - 5..21:  Device UUID (16 bytes)
//! - 21..53: Pre-Shared Key PSK (32 bytes)
//! - 53..57: Server IPv4 Address (4 bytes)
//! - 57..59: Server TCP Port (2 bytes, big-endian)
//! - 59..63: CRC32 IEEE 802.3 checksum of bytes 0..59 (4 bytes, big-endian)

use crate::packet::{ByteReader, ByteWriter};

/// Compute IEEE 802.3 CRC32 checksum (polynomial 0xEDB88320) bit-by-bit.
/// Completely tableless, zero memory overhead, pure safe code.
pub fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            let mask = -((crc & 1) as i32) as u32;
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProvisioningError {
    BufferTooShort,
    InvalidMagic,
    UnsupportedVersion,
    ChecksumMismatch,
    IoError(libc::c_int),
}

pub const DEV_DEVICE_UUID: [u8; 16] = *b"TRILLBY_0001\0\0\0\0";
pub const DEV_PSK: [u8; 32] = [0x42; 32];
pub const DEFAULT_SERVER_PORT: u16 = 8088;
pub const DEFAULT_PATH: &str = "/etc/trillby/device.key";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceProvisioning {
    pub device_uuid: [u8; 16],
    pub psk: [u8; 32],
    pub server_ip: [u8; 4],
    pub server_port: u16,
}

impl DeviceProvisioning {
    pub const LEN: usize = 63;
    pub const MAGIC: [u8; 4] = *b"TRPV";
    pub const VERSION: u8 = 1;
    pub const CRC_OFFSET: usize = Self::LEN - 4;
    pub fn new(device_uuid: [u8; 16], psk: [u8; 32], server_ip: [u8; 4], server_port: u16) -> Self {
        Self {
            device_uuid,
            psk,
            server_ip,
            server_port,
        }
    }
    pub fn dev_fallback(server_ip: [u8; 4]) -> Self {
        Self {
            device_uuid: DEV_DEVICE_UUID,
            psk: DEV_PSK,
            server_ip,
            server_port: DEFAULT_SERVER_PORT,
        }
    }


    /// Encode provisioning blob with header and IEEE CRC32 into a fixed 63-byte buffer.
    pub fn encode(&self, out: &mut [u8; Self::LEN]) {
        let mut w = ByteWriter::new(out);
        let _ = w.write_bytes(&Self::MAGIC);
        let _ = w.write_bytes(&[Self::VERSION]);
        let _ = w.write_bytes(&self.device_uuid);
        let _ = w.write_bytes(&self.psk);
        let _ = w.write_bytes(&self.server_ip);
        let _ = w.write_bytes(&self.server_port.to_be_bytes());

        let crc = crc32_ieee(w.written());
        let _ = w.write_bytes(&crc.to_be_bytes());
    }

    /// Decode and verify integrity of a provisioning blob from raw bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProvisioningError> {
        if bytes.len() < Self::LEN {
            return Err(ProvisioningError::BufferTooShort);
        }
        let mut r = ByteReader::new(&bytes[..Self::CRC_OFFSET]);
        let magic: [u8; 4] = r.read_array().map_err(|_| ProvisioningError::BufferTooShort)?;
        if magic != Self::MAGIC {
            return Err(ProvisioningError::InvalidMagic);
        }
        let version = r.read_u8().map_err(|_| ProvisioningError::BufferTooShort)?;
        if version != Self::VERSION {
            return Err(ProvisioningError::UnsupportedVersion);
        }

        let computed_crc = crc32_ieee(&bytes[..Self::CRC_OFFSET]);
        let expected_crc = u32::from_be_bytes(bytes[Self::CRC_OFFSET..Self::LEN].try_into().unwrap());
        if computed_crc != expected_crc {
            return Err(ProvisioningError::ChecksumMismatch);
        }

        let device_uuid = r.read_array().map_err(|_| ProvisioningError::BufferTooShort)?;
        let psk = r.read_array().map_err(|_| ProvisioningError::BufferTooShort)?;
        let server_ip = r.read_array().map_err(|_| ProvisioningError::BufferTooShort)?;
        let server_port_bytes: [u8; 2] = r.read_array().map_err(|_| ProvisioningError::BufferTooShort)?;
        let server_port = u16::from_be_bytes(server_port_bytes);

        Ok(Self {
            device_uuid,
            psk,
            server_ip,
            server_port,
        })
    }

    /// Load provisioning credentials from a local file path using zero-allocation POSIX syscalls.
    pub fn load_from_file(path: &str) -> Result<Self, ProvisioningError> {
        let mut path_buf = [0u8; 256];
        if path.len() >= path_buf.len() {
            return Err(ProvisioningError::IoError(libc::ENAMETOOLONG));
        }
        if path.as_bytes().contains(&0) {
            return Err(ProvisioningError::IoError(libc::EINVAL));
        }
        path_buf[..path.len()].copy_from_slice(path.as_bytes());
        path_buf[path.len()] = 0;
        let fd = unsafe {
            libc::open(
                path_buf.as_ptr() as *const libc::c_char,
                libc::O_RDONLY | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            let err = unsafe { *libc::__errno_location() };
            return Err(ProvisioningError::IoError(err));
        }

        let mut buf = [0u8; Self::LEN];
        let mut offset = 0;
        while offset < buf.len() {
            let n = unsafe {
                libc::read(
                    fd,
                    buf[offset..].as_mut_ptr() as *mut libc::c_void,
                    buf.len() - offset,
                )
            };
            if n > 0 {
                offset += n as usize;
            } else if n == 0 {
                break;
            } else {
                let err = unsafe { *libc::__errno_location() };
                if err == libc::EINTR {
                    continue;
                }
                unsafe { libc::close(fd); }
                return Err(ProvisioningError::IoError(err));
            }
        }
        unsafe { libc::close(fd); }

        if offset < Self::LEN {
            return Err(ProvisioningError::BufferTooShort);
        }

        Self::decode(&buf)
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryError {
    MalformedEntry,
}

pub fn decode_hex<const N: usize>(s: &str) -> Option<[u8; N]> {
    let s = s.as_bytes();
    if s.len() != N * 2 {
        return None;
    }
    let nib = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    };
    let mut out = [0u8; N];
    for (i, o) in out.iter_mut().enumerate() {
        *o = (nib(s[i * 2])? << 4) | nib(s[i * 2 + 1])?;
    }
    Some(out)
}

pub fn write_hex(out: &mut impl core::fmt::Write, bytes: &[u8]) -> core::fmt::Result {
    for &b in bytes {
        write!(out, "{b:02x}")?;
    }
    Ok(())
}

#[allow(clippy::type_complexity)]
pub fn parse_registry_line(line: &str) -> Result<Option<([u8; 16], [u8; 32])>, RegistryError> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return Ok(None);
    }
    let mut cols = line.split_whitespace();
    let uuid = cols.next().and_then(decode_hex::<16>).ok_or(RegistryError::MalformedEntry)?;
    let psk = cols.next().and_then(decode_hex::<32>).ok_or(RegistryError::MalformedEntry)?;
    Ok(Some((uuid, psk)))
}

pub fn write_registry_line(
    out: &mut impl core::fmt::Write,
    uuid: &[u8; 16],
    psk: &[u8; 32],
    timestamp: u64,
) -> core::fmt::Result {
    write_hex(out, uuid)?;
    out.write_char('\t')?;
    write_hex(out, psk)?;
    out.write_char('\t')?;
    writeln!(out, "{timestamp}")
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use std::format;

    #[test]
    fn test_crc32_ieee_known_vectors() {
        assert_eq!(crc32_ieee(b""), 0x00000000);
        assert_eq!(crc32_ieee(b"123456789"), 0xCBF43926);
    }

    fn sample_blob() -> (DeviceProvisioning, [u8; DeviceProvisioning::LEN]) {
        let creds = DeviceProvisioning {
            device_uuid: [0x42; 16],
            psk: [0x99; 32],
            server_ip: [192, 168, 1, 50],
            server_port: 8088,
        };
        let mut blob = [0u8; DeviceProvisioning::LEN];
        creds.encode(&mut blob);
        (creds, blob)
    }

    #[test]
    fn test_device_provisioning_round_trip_and_tamper() {
        let (creds, blob) = sample_blob();

        // Valid decode
        let decoded = DeviceProvisioning::decode(&blob).expect("valid decode");
        assert_eq!(decoded, creds);

        // Checksum mismatch on 1 bit flip
        let mut corrupted = blob;
        corrupted[10] ^= 0x01;
        assert_eq!(
            DeviceProvisioning::decode(&corrupted),
            Err(ProvisioningError::ChecksumMismatch)
        );

        // Invalid magic
        let mut bad_magic = blob;
        bad_magic[0] = b'X';
        assert_eq!(
            DeviceProvisioning::decode(&bad_magic),
            Err(ProvisioningError::InvalidMagic)
        );
    }

    #[test]
    fn test_decode_short_and_unsupported_version() {
        assert_eq!(
            DeviceProvisioning::decode(&[0u8; DeviceProvisioning::LEN - 1]),
            Err(ProvisioningError::BufferTooShort)
        );

        let (_creds, blob) = sample_blob();

        // Version 0
        let mut v0_blob = blob;
        v0_blob[4] = 0;
        assert_eq!(
            DeviceProvisioning::decode(&v0_blob),
            Err(ProvisioningError::UnsupportedVersion)
        );

        // Version 2
        let mut v2_blob = blob;
        v2_blob[4] = 2;
        assert_eq!(
            DeviceProvisioning::decode(&v2_blob),
            Err(ProvisioningError::UnsupportedVersion)
        );
    }

    #[test]
    fn test_load_from_file_lifecycle_and_errors() {
        let creds = DeviceProvisioning {
            device_uuid: [0x11; 16],
            psk: [0x22; 32],
            server_ip: [10, 0, 0, 1],
            server_port: 9000,
        };
        let mut blob = [0u8; DeviceProvisioning::LEN];
        creds.encode(&mut blob);

        let pid = std::process::id();
        let valid_path = format!("/tmp/trillby_prov_test_{}_valid.bin", pid);
        let trunc_path = format!("/tmp/trillby_prov_test_{}_trunc.bin", pid);
        let corrupt_path = format!("/tmp/trillby_prov_test_{}_corrupt.bin", pid);
        let missing_path = format!("/tmp/trillby_prov_test_{}_missing.bin", pid);

        // Clean up any stale files
        let _ = std::fs::remove_file(&valid_path);
        let _ = std::fs::remove_file(&trunc_path);
        let _ = std::fs::remove_file(&corrupt_path);
        let _ = std::fs::remove_file(&missing_path);

        std::fs::write(&valid_path, &blob).expect("write valid prov blob");

        // 1. Valid load
        let loaded = DeviceProvisioning::load_from_file(&valid_path).expect("load valid blob");
        assert_eq!(loaded, creds);

        // 2. Missing file
        assert_eq!(
            DeviceProvisioning::load_from_file(&missing_path),
            Err(ProvisioningError::IoError(libc::ENOENT))
        );

        // 3. Path >= 256 bytes
        let long_path = "a".repeat(256);
        assert_eq!(
            DeviceProvisioning::load_from_file(&long_path),
            Err(ProvisioningError::IoError(libc::ENAMETOOLONG))
        );

        // 4. Truncated 62-byte file
        std::fs::write(&trunc_path, &blob[..62]).expect("write truncated prov blob");
        assert_eq!(
            DeviceProvisioning::load_from_file(&trunc_path),
            Err(ProvisioningError::BufferTooShort)
        );

        // 5. Corrupted CRC file
        let mut corrupted_blob = blob;
        corrupted_blob[10] ^= 0x01;
        std::fs::write(&corrupt_path, &corrupted_blob).expect("write corrupt prov blob");
        assert_eq!(
            DeviceProvisioning::load_from_file(&corrupt_path),
            Err(ProvisioningError::ChecksumMismatch)
        );

        // 6. Path with interior NUL byte: must be rejected with Err rather than silently opening valid_path
        let nul_path = format!("{}\0/trailing", valid_path);
        assert!(DeviceProvisioning::load_from_file(&nul_path).is_err());

        // Cleanup
        let _ = std::fs::remove_file(&valid_path);
        let _ = std::fs::remove_file(&trunc_path);
        let _ = std::fs::remove_file(&corrupt_path);
    }


    #[test]
    fn test_decode_hex_and_write_hex() {
        let hex_16 = "000102030405060708090a0b0c0d0e0f";
        let expected = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        ];
        assert_eq!(decode_hex::<16>(hex_16), Some(expected));
        assert_eq!(decode_hex::<16>("000102030405060708090A0B0C0D0E0F"), Some(expected));
        assert_eq!(decode_hex::<16>("000102030405060708090a0B0c0D0e0F"), Some(expected));
        assert_eq!(decode_hex::<16>("123"), None);
        assert_eq!(decode_hex::<16>("000102030405060708090a0b0c0d0e0g"), None);

        let mut out_str = std::string::String::new();
        write_hex(&mut out_str, &expected).unwrap();
        assert_eq!(out_str, hex_16);
    }

    #[test]
    fn test_parse_and_write_registry_line() {
        let uuid = [0x12; 16];
        let psk = [0x34; 32];
        let ts = 1700000000u64;

        let mut line = std::string::String::new();
        write_registry_line(&mut line, &uuid, &psk, ts).unwrap();
        assert!(line.ends_with('\n'));

        let parsed = parse_registry_line(&line).unwrap();
        assert_eq!(parsed, Some((uuid, psk)));

        // Blank and comments
        assert_eq!(parse_registry_line(""), Ok(None));
        assert_eq!(parse_registry_line("   "), Ok(None));
        assert_eq!(parse_registry_line("# comment"), Ok(None));
        assert_eq!(parse_registry_line("  # indented comment"), Ok(None));

        // Malformed entries
        assert_eq!(parse_registry_line("bad_hex"), Err(RegistryError::MalformedEntry));
        assert_eq!(parse_registry_line("00112233445566778899aabbccddeeff"), Err(RegistryError::MalformedEntry));
        assert_eq!(parse_registry_line("00112233445566778899aabbccddeeff bad_psk"), Err(RegistryError::MalformedEntry));
    }
}
