use std::io::{Read, Write, Seek};
use anyhow::Result;
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

pub struct MockDevice {
    pub data: std::io::Cursor<Vec<u8>>,
}

impl MockDevice {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data: std::io::Cursor::new(data) }
    }
}

impl Read for MockDevice {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.data.read(buf)
    }
}

impl Write for MockDevice {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.data.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.data.flush()
    }
}

impl Seek for MockDevice {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        self.data.seek(pos)
    }
}

impl IoDelegate for MockDevice {
    fn get_size(&mut self) -> Result<usize> {
        Ok(self.data.get_ref().len())
    }
}
