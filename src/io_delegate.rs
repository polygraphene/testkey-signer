use std::io::{Read, Write, Seek};
use anyhow::{Result, anyhow};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::os::unix::io::AsRawFd;

pub trait IoDelegate: Read + Write + Seek {
    fn get_size(&mut self) -> Result<usize>;
}

pub struct RealDevice {
    file: std::fs::File,
    is_device: bool,
}

impl RealDevice {
    pub fn new(file: std::fs::File, is_device: bool) -> Self {
        Self { file, is_device }
    }
}

impl Read for RealDevice {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.file.read(buf)
    }
}

impl Write for RealDevice {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.file.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

impl Seek for RealDevice {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        self.file.seek(pos)
    }
}

impl IoDelegate for RealDevice {
    fn get_size(&mut self) -> Result<usize> {
        if self.is_device {
            const BLKGETSIZE64_CODE: u8 = 0x12; // Defined in linux/fs.h
            const BLKGETSIZE64_SEQ: u8 = 114;
            ioctl_read!(ioctl_blkgetsize64, BLKGETSIZE64_CODE, BLKGETSIZE64_SEQ, u64);
            let mut size64 = 0u64;
            let size64_ptr = &mut size64 as *mut u64;
            
            unsafe {
                ioctl_blkgetsize64(self.file.as_raw_fd(), size64_ptr)?;
            }
            Ok(size64 as usize)
        } else {
            Ok(self.file.metadata()?.len() as usize)
        }
    }
}

#[derive(Clone)]
pub struct MockDevice {
    pub data: Arc<Mutex<std::io::Cursor<Vec<u8>>>>,
}

impl MockDevice {
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            data: Arc::new(Mutex::new(std::io::Cursor::new(data))),
        }
    }

    pub fn into_inner(&self) -> Vec<u8> {
        self.data.lock().unwrap().get_ref().clone()
    }
}

impl Read for MockDevice {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.data.lock().unwrap().read(buf)
    }
}

impl Write for MockDevice {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.data.lock().unwrap().write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.data.lock().unwrap().flush()
    }
}

impl Seek for MockDevice {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        self.data.lock().unwrap().seek(pos)
    }
}

impl IoDelegate for MockDevice {
    fn get_size(&mut self) -> Result<usize> {
        Ok(self.data.lock().unwrap().get_ref().len())
    }
}

pub trait Environment {
    fn get_prop(&self, name: &str) -> Result<String>;
    fn open_device(&self, name: &str, is_device: bool, write: bool) -> Result<Box<dyn IoDelegate>>;
    fn device_exists(&self, name: &str) -> bool;
}

pub struct RealEnvironment;

impl Environment for RealEnvironment {
    #[cfg(target_os = "android")]
    fn get_prop(&self, name: &str) -> Result<String> {
        unsafe extern "C" {
            fn __system_property_get(name: *const u8, value: *mut u8) -> i32;
        }

        let mut value = vec![0u8; 1024];
        let len = unsafe { __system_property_get((name.to_string() + "\0").as_ptr(), value.as_mut_ptr()) } as usize;
        if len == 0 {
            Err(anyhow!("Property {name} not found"))
        } else {
            value.resize(len, 0);
            Ok(String::from_utf8(value)?)
        }
    }

    #[cfg(not(target_os = "android"))]
    fn get_prop(&self, _name: &str) -> Result<String> {
        Err(anyhow!("Not running on Android"))
    }

    fn open_device(&self, name: &str, is_device: bool, write: bool) -> Result<Box<dyn IoDelegate>> {
        let mut file_opts = std::fs::OpenOptions::new();
        file_opts.read(true);
        if write {
            file_opts.write(true);
        }
        let f = file_opts.open(name)?;
        Ok(Box::new(RealDevice::new(f, is_device)))
    }

    fn device_exists(&self, name: &str) -> bool {
        let mut file_opts = std::fs::OpenOptions::new();
        file_opts.read(true);
        file_opts.open(name).is_ok()
    }
}

pub struct MockEnvironment {
    pub props: HashMap<String, String>,
    pub devices: std::sync::Mutex<HashMap<String, MockDevice>>,
}

impl Environment for MockEnvironment {
    fn get_prop(&self, name: &str) -> Result<String> {
        self.props.get(name).cloned().ok_or_else(|| anyhow!("Property {name} not found in MockEnvironment"))
    }

    fn open_device(&self, name: &str, _is_device: bool, _write: bool) -> Result<Box<dyn IoDelegate>> {
        let devices = self.devices.lock().unwrap();
        let mut device = devices.get(name).ok_or_else(|| anyhow!("Device {name} not found in MockEnvironment"))?.clone();
        // Need to reset cursor to mimic real block device behavior
        // TODO: It breaks when multiple handles are opened
        device.seek(std::io::SeekFrom::Start(0))?;
        Ok(Box::new(device))
    }

    fn device_exists(&self, name: &str) -> bool {
        let devices = self.devices.lock().unwrap();
        devices.contains_key(name)
    }
}
