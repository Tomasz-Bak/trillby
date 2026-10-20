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

extern crate libc;

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

    pub fn new(device_uuid: [u8; 16], psk: [u8; 32], server_ip: [u8; 4], server_port: u16) -> Self {
        Self {
            device_uuid,
            psk,
            server_ip,
            server_port,
        }
    }

    /// Encode provisioning blob with header and IEEE CRC32 into a fixed 63-byte buffer.
    pub fn encode(&self, out: &mut [u8; Self::LEN]) {
        out[0..4].copy_from_slice(&Self::MAGIC);
        out[4] = Self::VERSION;
        out[5..21].copy_from_slice(&self.device_uuid);
        out[21..53].copy_from_slice(&self.psk);
        out[53..57].copy_from_slice(&self.server_ip);
        out[57..59].copy_from_slice(&self.server_port.to_be_bytes());

        let crc = crc32_ieee(&out[0..59]);
        out[59..63].copy_from_slice(&crc.to_be_bytes());
    }

    /// Decode and verify integrity of a provisioning blob from raw bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProvisioningError> {
        if bytes.len() < Self::LEN {
            return Err(ProvisioningError::BufferTooShort);
        }
        if bytes[0..4] != Self::MAGIC {
            return Err(ProvisioningError::InvalidMagic);
        }
        if bytes[4] != Self::VERSION {
            return Err(ProvisioningError::UnsupportedVersion);
        }

        let computed_crc = crc32_ieee(&bytes[0..59]);
        let expected_crc = u32::from_be_bytes([bytes[59], bytes[60], bytes[61], bytes[62]]);
        if computed_crc != expected_crc {
            return Err(ProvisioningError::ChecksumMismatch);
        }

        let mut device_uuid = [0u8; 16];
        device_uuid.copy_from_slice(&bytes[5..21]);

        let mut psk = [0u8; 32];
        psk.copy_from_slice(&bytes[21..53]);

        let mut server_ip = [0u8; 4];
        server_ip.copy_from_slice(&bytes[53..57]);

        let server_port = u16::from_be_bytes([bytes[57], bytes[58]]);

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crc32_ieee_known_vectors() {
        assert_eq!(crc32_ieee(b""), 0x00000000);
        assert_eq!(crc32_ieee(b"123456789"), 0xCBF43926);
    }

    #[test]
    fn test_device_provisioning_round_trip_and_tamper() {
        let creds = DeviceProvisioning {
            device_uuid: [0x42; 16],
            psk: [0x99; 32],
            server_ip: [192, 168, 1, 50],
            server_port: 8088,
        };

        let mut blob = [0u8; DeviceProvisioning::LEN];
        creds.encode(&mut blob);

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
}
