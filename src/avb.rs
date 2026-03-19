// Based on bindgen output of libavb headers.

#![allow(non_camel_case_types, non_snake_case, unused)]
#![no_std]
use std::mem::size_of;

use num_bigint_dig::BigUint;
use rsa::RsaPrivateKey;
use rsa::RsaPublicKey;
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs1v15::VerifyingKey;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::signature::hazmat::PrehashVerifier;
use rsa::traits::PublicKeyParts;
use num_bigint_dig::BigInt;
use num_bigint_dig::ExtendedGcd;
use num_traits::ToPrimitive;
use num_traits::identities::One;
use zerocopy::{FromBytes, FromZeros, Immutable, IntoBytes, KnownLayout};

use anyhow::Result;
use anyhow::anyhow;

use log::info;
use log::warn;
use log::error;
use log::debug;

use crate::hasher::Hasher;
use crate::io_delegate::IoDelegate;
use crate::pad_right;
use crate::padding_size;

pub const FOOTER_SIZE: usize = size_of::<AvbFooter>();
const HEADER_SIZE: usize = size_of::<AvbVBMetaImageHeader>();
const AVB_DESCRIPTOR_SIZE: usize = size_of::<AvbDescriptor>();
const HASH_DESCRIPTOR_SIZE: usize = size_of::<AvbHashDescriptor>();
pub const PUBLIC_EXPONENT: u32 = 65537u32;
pub const VBMETA_ALIGN: usize = 64;
const DESCRIPTOR_ALIGN: usize = 8;

pub const AVB_ALIGNMENT_SIZE: u32 = 8;
pub const AVB_RSA2048_NUM_BYTES: u32 = 256;
pub const AVB_RSA4096_NUM_BYTES: u32 = 512;
pub const AVB_RSA8192_NUM_BYTES: u32 = 1024;
pub const AVB_SHA1_DIGEST_SIZE: u32 = 20;
pub const AVB_SHA256_DIGEST_SIZE: u32 = 32;
pub const AVB_SHA512_DIGEST_SIZE: u32 = 64;
pub const AVB_FOOTER_MAGIC: &[u8; 5] = b"AVBf\0";
pub const AVB_FOOTER_MAGIC_LEN: u32 = 4;
pub const AVB_FOOTER_SIZE: u32 = 64;
pub const AVB_FOOTER_VERSION_MAJOR: u32 = 1;
pub const AVB_FOOTER_VERSION_MINOR: u32 = 0;
pub const AVB_NPV_PERSISTENT_DIGEST_PREFIX: &[u8; 23] = b"avb.persistent_digest.\0";
pub const AVB_NPV_MANAGED_VERITY_MODE: &[u8; 24] = b"avb.managed_verity_mode\0";
pub const AVB_VBMETA_IMAGE_HEADER_SIZE: u32 = 256;
pub const AVB_MAGIC: &[u8; 5] = b"AVB0\0";
pub const AVB_MAGIC_LEN: u32 = 4;
pub const AVB_RELEASE_STRING_SIZE: u32 = 48;
pub const AVB_MAX_NUMBER_OF_ROLLBACK_INDEX_LOCATIONS: u32 = 32;
pub const AVB_MAX_DIGITS_UINT64: u32 = 32;
pub const AVB_VERSION_MAJOR: u32 = 1;
pub const AVB_VERSION_MINOR: u32 = 3;
pub const AVB_VERSION_SUB: u32 = 0;
pub const AVB_CERT_PRODUCT_ID_SIZE: u32 = 16;
pub const AVB_CERT_UNLOCK_CHALLENGE_SIZE: u32 = 16;
pub const AVB_CERT_PIK_VERSION_LOCATION: u32 = 4096;
pub const AVB_CERT_PSK_VERSION_LOCATION: u32 = 4097;
pub type wchar_t = core::ffi::c_uint;
pub type uintmax_t = u64;
pub type intmax_t = i64;
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct imaxdiv_t {
    pub quot: intmax_t,
    pub rem: intmax_t,
}
#[test]
fn bindgen_test_layout_imaxdiv_t() {
    const UNINIT: ::core::mem::MaybeUninit<imaxdiv_t> = ::core::mem::MaybeUninit::uninit();
    let ptr = UNINIT.as_ptr();
    assert_eq!(
        ::core::mem::size_of::<imaxdiv_t>(),
        16usize,
        concat!("Size of: ", stringify!(imaxdiv_t))
    );
    assert_eq!(
        ::core::mem::align_of::<imaxdiv_t>(),
        8usize,
        concat!("Alignment of ", stringify!(imaxdiv_t))
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).quot) as usize - ptr as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(imaxdiv_t),
            "::",
            stringify!(quot)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).rem) as usize - ptr as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(imaxdiv_t),
            "::",
            stringify!(rem)
        )
    );
}
pub mod AvbDescriptorTag {
    pub type Type = core::ffi::c_uint;
    pub const AVB_DESCRIPTOR_TAG_PROPERTY: Type = 0;
    pub const AVB_DESCRIPTOR_TAG_HASHTREE: Type = 1;
    pub const AVB_DESCRIPTOR_TAG_HASH: Type = 2;
    pub const AVB_DESCRIPTOR_TAG_KERNEL_CMDLINE: Type = 3;
    pub const AVB_DESCRIPTOR_TAG_CHAIN_PARTITION: Type = 4;
}
#[repr(C, packed)]
#[derive(Debug, Default, Copy, Clone, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct AvbDescriptor {
    pub tag: u64,
    pub num_bytes_following: u64,
}
#[test]
fn bindgen_test_layout_AvbDescriptor() {
    const UNINIT: ::core::mem::MaybeUninit<AvbDescriptor> = ::core::mem::MaybeUninit::uninit();
    let ptr = UNINIT.as_ptr();
    assert_eq!(
        ::core::mem::size_of::<AvbDescriptor>(),
        16usize,
        concat!("Size of: ", stringify!(AvbDescriptor))
    );
    assert_eq!(
        ::core::mem::align_of::<AvbDescriptor>(),
        1usize,
        concat!("Alignment of ", stringify!(AvbDescriptor))
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).tag) as usize - ptr as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbDescriptor),
            "::",
            stringify!(tag)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).num_bytes_following) as usize - ptr as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbDescriptor),
            "::",
            stringify!(num_bytes_following)
        )
    );
}
impl AvbDescriptor {
    pub fn from_bytes(src: &[u8]) -> Result<Self> {
        if src.len() < AVB_DESCRIPTOR_SIZE {
            return Err(anyhow!("Invalid descriptor size"));
        }
        let mut descriptor = Self::new_zeroed();
        Self::to_host_byte_order(unsafe { &*(src.as_ptr() as *const Self) }, &mut descriptor);
        Ok(descriptor)
    }

    fn to_host_byte_order(&self, dest: &mut Self) {
        dest.tag = self.tag.to_be();
        dest.num_bytes_following = self.num_bytes_following.to_be();
    }
}
pub type AvbDescriptorForeachFunc = ::core::option::Option<
    unsafe extern "C" fn(
        descriptor: *const AvbDescriptor,
        user_data: *mut core::ffi::c_void,
    ) -> bool,
>;
impl AvbChainPartitionDescriptorFlags {
    pub const AVB_CHAIN_PARTITION_DESCRIPTOR_FLAGS_DO_NOT_USE_AB: AvbChainPartitionDescriptorFlags =
        AvbChainPartitionDescriptorFlags(1);
}
impl ::core::ops::BitOr<AvbChainPartitionDescriptorFlags> for AvbChainPartitionDescriptorFlags {
    type Output = Self;
    #[inline]
    fn bitor(self, other: Self) -> Self {
        AvbChainPartitionDescriptorFlags(self.0 | other.0)
    }
}
impl ::core::ops::BitOrAssign for AvbChainPartitionDescriptorFlags {
    #[inline]
    fn bitor_assign(&mut self, rhs: AvbChainPartitionDescriptorFlags) {
        self.0 |= rhs.0;
    }
}
impl ::core::ops::BitAnd<AvbChainPartitionDescriptorFlags> for AvbChainPartitionDescriptorFlags {
    type Output = Self;
    #[inline]
    fn bitand(self, other: Self) -> Self {
        AvbChainPartitionDescriptorFlags(self.0 & other.0)
    }
}
impl ::core::ops::BitAndAssign for AvbChainPartitionDescriptorFlags {
    #[inline]
    fn bitand_assign(&mut self, rhs: AvbChainPartitionDescriptorFlags) {
        self.0 &= rhs.0;
    }
}
#[repr(transparent)]
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub struct AvbChainPartitionDescriptorFlags(pub core::ffi::c_uint);
#[repr(C, packed)]
#[derive(Debug, Copy, Clone, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct AvbChainPartitionDescriptor {
    pub parent_descriptor: AvbDescriptor,
    pub rollback_index_location: u32,
    pub partition_name_len: u32,
    pub public_key_len: u32,
    pub flags: u32,
    pub reserved: [u8; 60usize],
}
#[test]
fn bindgen_test_layout_AvbChainPartitionDescriptor() {
    const UNINIT: ::core::mem::MaybeUninit<AvbChainPartitionDescriptor> =
        ::core::mem::MaybeUninit::uninit();
    let ptr = UNINIT.as_ptr();
    assert_eq!(
        ::core::mem::size_of::<AvbChainPartitionDescriptor>(),
        92usize,
        concat!("Size of: ", stringify!(AvbChainPartitionDescriptor))
    );
    assert_eq!(
        ::core::mem::align_of::<AvbChainPartitionDescriptor>(),
        1usize,
        concat!("Alignment of ", stringify!(AvbChainPartitionDescriptor))
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).parent_descriptor) as usize - ptr as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbChainPartitionDescriptor),
            "::",
            stringify!(parent_descriptor)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).rollback_index_location) as usize - ptr as usize },
        16usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbChainPartitionDescriptor),
            "::",
            stringify!(rollback_index_location)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).partition_name_len) as usize - ptr as usize },
        20usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbChainPartitionDescriptor),
            "::",
            stringify!(partition_name_len)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).public_key_len) as usize - ptr as usize },
        24usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbChainPartitionDescriptor),
            "::",
            stringify!(public_key_len)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).flags) as usize - ptr as usize },
        28usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbChainPartitionDescriptor),
            "::",
            stringify!(flags)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).reserved) as usize - ptr as usize },
        32usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbChainPartitionDescriptor),
            "::",
            stringify!(reserved)
        )
    );
}
impl Default for AvbChainPartitionDescriptor {
    fn default() -> Self {
        let mut s = ::core::mem::MaybeUninit::<Self>::uninit();
        unsafe {
            ::core::ptr::write_bytes(s.as_mut_ptr(), 0, 1);
            s.assume_init()
        }
    }
}
#[repr(u32)]
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub enum AvbDigestType {
    AVB_DIGEST_TYPE_SHA256 = 0,
    AVB_DIGEST_TYPE_SHA512 = 1,
}
#[repr(u32)]
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub enum AvbAlgorithmType {
    AVB_ALGORITHM_TYPE_NONE = 0,
    AVB_ALGORITHM_TYPE_SHA256_RSA2048 = 1,
    AVB_ALGORITHM_TYPE_SHA256_RSA4096 = 2,
    AVB_ALGORITHM_TYPE_SHA256_RSA8192 = 3,
    AVB_ALGORITHM_TYPE_SHA512_RSA2048 = 4,
    AVB_ALGORITHM_TYPE_SHA512_RSA4096 = 5,
    AVB_ALGORITHM_TYPE_SHA512_RSA8192 = 6,
    _AVB_ALGORITHM_NUM_TYPES = 7,
}
#[repr(C, packed)]
#[derive(Debug, Default, Copy, Clone, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct AvbRSAPublicKeyHeader {
    pub key_num_bits: u32,
    pub n0inv: u32,
}
#[test]
fn bindgen_test_layout_AvbRSAPublicKeyHeader() {
    const UNINIT: ::core::mem::MaybeUninit<AvbRSAPublicKeyHeader> =
        ::core::mem::MaybeUninit::uninit();
    let ptr = UNINIT.as_ptr();
    assert_eq!(
        ::core::mem::size_of::<AvbRSAPublicKeyHeader>(),
        8usize,
        concat!("Size of: ", stringify!(AvbRSAPublicKeyHeader))
    );
    assert_eq!(
        ::core::mem::align_of::<AvbRSAPublicKeyHeader>(),
        1usize,
        concat!("Alignment of ", stringify!(AvbRSAPublicKeyHeader))
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).key_num_bits) as usize - ptr as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbRSAPublicKeyHeader),
            "::",
            stringify!(key_num_bits)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).n0inv) as usize - ptr as usize },
        4usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbRSAPublicKeyHeader),
            "::",
            stringify!(n0inv)
        )
    );
}
impl AvbRSAPublicKeyHeader {
    pub fn from_bytes(src: &[u8]) -> Result<Self> {
        let mut dest = Self::new_zeroed();
        Self::ref_from_bytes(&src[0..size_of::<Self>()])
            .map_err(|f| anyhow!("Invalid public key header: {}", f))?
            .to_host_byte_order(&mut dest);
        Ok(dest)
    }

    pub fn to_be_bytes(&self) -> Vec<u8> {
        let mut dest = Self::new_zeroed();
        self.to_host_byte_order(&mut dest);
        dest.as_bytes().to_vec()
    }

    fn to_host_byte_order(&self, dest: &mut Self) {
        dest.key_num_bits = self.key_num_bits.to_be();
        dest.n0inv = self.n0inv.to_be();
    }
}

#[derive(Default)]
pub struct AvbRSAPublicKey {
    pub header: AvbRSAPublicKeyHeader,
    pub modulus: Vec<u8>,
    pub rr: Vec<u8>,
}
impl AvbRSAPublicKey {
    pub fn from_bytes(src: &[u8]) -> Result<Self> {
        let header = AvbRSAPublicKeyHeader::from_bytes(src)?;
        let modulus_size = header.key_num_bits as usize / 8;
        let rr_size = header.key_num_bits as usize / 8;
        if src.len() < size_of::<AvbRSAPublicKeyHeader>() + modulus_size + rr_size {
            return Err(anyhow!("Invalid public key"));
        }
        let mut offset = size_of::<AvbRSAPublicKeyHeader>();
        let modulus = src[offset..offset + modulus_size].to_vec();
        offset += modulus_size;
        let rr = src[offset..offset + rr_size].to_vec();
        Ok(Self { header, modulus, rr })
    }

    pub fn to_be_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];
        bytes.extend_from_slice(&self.header.to_be_bytes());
        bytes.extend_from_slice(&self.modulus);
        bytes.extend_from_slice(&self.rr);
        bytes
    }
}


#[repr(C, packed)]
#[derive(Debug, Default, Copy, Clone, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct AvbFooter {
    pub magic: [u8; 4usize],
    pub version_major: u32,
    pub version_minor: u32,
    pub original_image_size: u64,
    pub vbmeta_offset: u64,
    pub vbmeta_size: u64,
    pub reserved: [u8; 28usize],
}
#[test]
fn bindgen_test_layout_AvbFooter() {
    const UNINIT: ::core::mem::MaybeUninit<AvbFooter> = ::core::mem::MaybeUninit::uninit();
    let ptr = UNINIT.as_ptr();
    assert_eq!(
        ::core::mem::size_of::<AvbFooter>(),
        64usize,
        concat!("Size of: ", stringify!(AvbFooter))
    );
    assert_eq!(
        ::core::mem::align_of::<AvbFooter>(),
        1usize,
        concat!("Alignment of ", stringify!(AvbFooter))
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).magic) as usize - ptr as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbFooter),
            "::",
            stringify!(magic)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).version_major) as usize - ptr as usize },
        4usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbFooter),
            "::",
            stringify!(version_major)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).version_minor) as usize - ptr as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbFooter),
            "::",
            stringify!(version_minor)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).original_image_size) as usize - ptr as usize },
        12usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbFooter),
            "::",
            stringify!(original_image_size)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).vbmeta_offset) as usize - ptr as usize },
        20usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbFooter),
            "::",
            stringify!(vbmeta_offset)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).vbmeta_size) as usize - ptr as usize },
        28usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbFooter),
            "::",
            stringify!(vbmeta_size)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).reserved) as usize - ptr as usize },
        36usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbFooter),
            "::",
            stringify!(reserved)
        )
    );
}
impl AvbFooter {
    pub fn from_file(f: &mut dyn IoDelegate) -> Result<Option<Self>> {
        let mut footer_bytes = vec![0u8; FOOTER_SIZE];
        f.seek(std::io::SeekFrom::End(-(FOOTER_SIZE as i64)))?;
        f.read_exact(&mut footer_bytes)?;

        Ok(Self::from_bytes(&footer_bytes)?)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Option<Self>> {
        if bytes.len() < FOOTER_SIZE {
            return Err(anyhow!("Invalid footer size"));
        }
        let mut footer = Self::new_zeroed();
        Self::to_host_byte_order(unsafe { &*(bytes.as_ptr() as *const Self) }, &mut footer);
        if footer.magic != AVB_FOOTER_MAGIC[0..4] {
            return Ok(None);
        }
        Ok(Some(footer))
    }

    pub fn to_be_bytes(&self) -> Vec<u8> {
        let mut dest = Self::new_zeroed();
        self.to_host_byte_order(&mut dest);
        dest.as_bytes().to_vec()
    }

    fn to_host_byte_order(&self, dest: &mut Self) {
        dest.magic = self.magic;
        dest.version_major = self.version_major.to_be();
        dest.version_minor = self.version_minor.to_be();
        dest.original_image_size = self.original_image_size.to_be();
        dest.vbmeta_offset = self.vbmeta_offset.to_be();
        dest.vbmeta_size = self.vbmeta_size.to_be();
    }

    pub fn file_has_footer(f: &mut dyn IoDelegate) -> Result<bool> {
        let footer = AvbFooter::from_file(f)?;

        Ok(footer.map_or(false, |f| f.magic == AVB_FOOTER_MAGIC[0..4]))
    }
}
impl AvbHashDescriptorFlags {
    pub const AVB_HASH_DESCRIPTOR_FLAGS_DO_NOT_USE_AB: AvbHashDescriptorFlags =
        AvbHashDescriptorFlags(1);
}
impl ::core::ops::BitOr<AvbHashDescriptorFlags> for AvbHashDescriptorFlags {
    type Output = Self;
    #[inline]
    fn bitor(self, other: Self) -> Self {
        AvbHashDescriptorFlags(self.0 | other.0)
    }
}
impl ::core::ops::BitOrAssign for AvbHashDescriptorFlags {
    #[inline]
    fn bitor_assign(&mut self, rhs: AvbHashDescriptorFlags) {
        self.0 |= rhs.0;
    }
}
impl ::core::ops::BitAnd<AvbHashDescriptorFlags> for AvbHashDescriptorFlags {
    type Output = Self;
    #[inline]
    fn bitand(self, other: Self) -> Self {
        AvbHashDescriptorFlags(self.0 & other.0)
    }
}
impl ::core::ops::BitAndAssign for AvbHashDescriptorFlags {
    #[inline]
    fn bitand_assign(&mut self, rhs: AvbHashDescriptorFlags) {
        self.0 &= rhs.0;
    }
}
#[repr(transparent)]
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub struct AvbHashDescriptorFlags(pub core::ffi::c_uint);
#[repr(C, packed)]
#[derive(Debug, Copy, Clone, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct AvbHashDescriptor {
    pub parent_descriptor: AvbDescriptor,
    pub image_size: u64,
    pub hash_algorithm: [u8; 32usize],
    pub partition_name_len: u32,
    pub salt_len: u32,
    pub digest_len: u32,
    pub flags: u32,
    pub reserved: [u8; 60usize],
}
#[test]
fn bindgen_test_layout_AvbHashDescriptor() {
    const UNINIT: ::core::mem::MaybeUninit<AvbHashDescriptor> = ::core::mem::MaybeUninit::uninit();
    let ptr = UNINIT.as_ptr();
    assert_eq!(
        ::core::mem::size_of::<AvbHashDescriptor>(),
        132usize,
        concat!("Size of: ", stringify!(AvbHashDescriptor))
    );
    assert_eq!(
        ::core::mem::align_of::<AvbHashDescriptor>(),
        1usize,
        concat!("Alignment of ", stringify!(AvbHashDescriptor))
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).parent_descriptor) as usize - ptr as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbHashDescriptor),
            "::",
            stringify!(parent_descriptor)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).image_size) as usize - ptr as usize },
        16usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbHashDescriptor),
            "::",
            stringify!(image_size)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).hash_algorithm) as usize - ptr as usize },
        24usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbHashDescriptor),
            "::",
            stringify!(hash_algorithm)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).partition_name_len) as usize - ptr as usize },
        56usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbHashDescriptor),
            "::",
            stringify!(partition_name_len)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).salt_len) as usize - ptr as usize },
        60usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbHashDescriptor),
            "::",
            stringify!(salt_len)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).digest_len) as usize - ptr as usize },
        64usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbHashDescriptor),
            "::",
            stringify!(digest_len)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).flags) as usize - ptr as usize },
        68usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbHashDescriptor),
            "::",
            stringify!(flags)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).reserved) as usize - ptr as usize },
        72usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbHashDescriptor),
            "::",
            stringify!(reserved)
        )
    );
}
impl AvbHashDescriptor {
    pub fn from_bytes(src: &[u8]) -> Result<Self> {
        if src.len() < size_of::<AvbHashDescriptor>() {
            return Err(anyhow!("Invalid descriptor"));
        }
        let mut descriptor = Self::new_zeroed();
        Self::to_host_byte_order(unsafe { &*(src.as_ptr() as *const Self) }, &mut descriptor);

        Ok(descriptor)
    }

    fn to_host_byte_order(&self, dest: &mut Self) {
        dest.parent_descriptor.tag = self.parent_descriptor.tag.to_be();
        dest.parent_descriptor.num_bytes_following = self.parent_descriptor.num_bytes_following.to_be();
        dest.image_size = self.image_size.to_be();
        dest.hash_algorithm = self.hash_algorithm;
        dest.partition_name_len = self.partition_name_len.to_be();
        dest.salt_len = self.salt_len.to_be();
        dest.digest_len = self.digest_len.to_be();
        dest.flags = self.flags.to_be();
        dest.reserved = self.reserved;
    }

    fn to_be_bytes(&self) -> [u8; size_of::<Self>()] {
        let mut bytes = [0u8; size_of::<Self>()];
        self.to_host_byte_order(unsafe { &mut *(bytes.as_mut_ptr() as *mut Self) });
        bytes
    }

    pub fn algorithm_name(&self) -> String {
        String::from_utf8_lossy(&self.hash_algorithm).trim_end_matches('\0').to_string()
    }
}
impl Default for AvbHashDescriptor {
    fn default() -> Self {
        let mut s = ::core::mem::MaybeUninit::<Self>::uninit();
        unsafe {
            ::core::ptr::write_bytes(s.as_mut_ptr(), 0, 1);
            s.assume_init()
        }
    }
}
#[derive(Clone)]
pub struct AvbHashDescriptorInfo {
    pub descriptor: AvbHashDescriptor,
    pub partition_name: Vec<u8>,
    pub salt: Vec<u8>,
    pub digest: Vec<u8>,
}
impl AvbHashDescriptorInfo {
    pub fn from_bytes(src: &[u8]) -> Result<Self> {
        let descriptor = AvbHashDescriptor::from_bytes(src)?;

        let mut offset = size_of::<AvbHashDescriptor>();
        let partition_name = src[offset..offset + descriptor.partition_name_len as usize].to_vec();
        offset += descriptor.partition_name_len as usize;
        let salt = src[offset..offset + descriptor.salt_len as usize].to_vec();
        offset += descriptor.salt_len as usize;
        let digest = src[offset..offset + descriptor.digest_len as usize].to_vec();

        Ok(Self {
            descriptor,
            partition_name,
            salt,
            digest,
        })
    }

    pub fn fix_header(&mut self) {
        self.descriptor.partition_name_len = self.partition_name.len() as u32;
        self.descriptor.salt_len = self.salt.len() as u32;
        self.descriptor.digest_len = self.digest.len() as u32;
        self.descriptor.parent_descriptor.num_bytes_following = (size_of::<AvbHashDescriptor>() - AVB_DESCRIPTOR_SIZE + self.partition_name.len() + self.salt.len() + self.digest.len()) as u64;
        self.descriptor.parent_descriptor.num_bytes_following += padding_size(self.descriptor.parent_descriptor.num_bytes_following as usize, DESCRIPTOR_ALIGN) as u64;
    }

    pub fn to_be_bytes(&self) -> Vec<u8> {
        let mut bytes = self.descriptor.to_be_bytes().to_vec();
        bytes.extend_from_slice(&self.partition_name);
        bytes.extend_from_slice(&self.salt);
        bytes.extend_from_slice(&self.digest);
        pad_right(&mut bytes, DESCRIPTOR_ALIGN);
        bytes
    }
}
impl AvbHashtreeDescriptorFlags {
    pub const AVB_HASHTREE_DESCRIPTOR_FLAGS_DO_NOT_USE_AB: AvbHashtreeDescriptorFlags =
        AvbHashtreeDescriptorFlags(1);
}
impl AvbHashtreeDescriptorFlags {
    pub const AVB_HASHTREE_DESCRIPTOR_FLAGS_CHECK_AT_MOST_ONCE: AvbHashtreeDescriptorFlags =
        AvbHashtreeDescriptorFlags(2);
}
impl ::core::ops::BitOr<AvbHashtreeDescriptorFlags> for AvbHashtreeDescriptorFlags {
    type Output = Self;
    #[inline]
    fn bitor(self, other: Self) -> Self {
        AvbHashtreeDescriptorFlags(self.0 | other.0)
    }
}
impl ::core::ops::BitOrAssign for AvbHashtreeDescriptorFlags {
    #[inline]
    fn bitor_assign(&mut self, rhs: AvbHashtreeDescriptorFlags) {
        self.0 |= rhs.0;
    }
}
impl ::core::ops::BitAnd<AvbHashtreeDescriptorFlags> for AvbHashtreeDescriptorFlags {
    type Output = Self;
    #[inline]
    fn bitand(self, other: Self) -> Self {
        AvbHashtreeDescriptorFlags(self.0 & other.0)
    }
}
impl ::core::ops::BitAndAssign for AvbHashtreeDescriptorFlags {
    #[inline]
    fn bitand_assign(&mut self, rhs: AvbHashtreeDescriptorFlags) {
        self.0 &= rhs.0;
    }
}
#[repr(transparent)]
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub struct AvbHashtreeDescriptorFlags(pub core::ffi::c_uint);
#[repr(C, packed)]
#[derive(Debug, Copy, Clone, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct AvbHashtreeDescriptor {
    pub parent_descriptor: AvbDescriptor,
    pub dm_verity_version: u32,
    pub image_size: u64,
    pub tree_offset: u64,
    pub tree_size: u64,
    pub data_block_size: u32,
    pub hash_block_size: u32,
    pub fec_num_roots: u32,
    pub fec_offset: u64,
    pub fec_size: u64,
    pub hash_algorithm: [u8; 32usize],
    pub partition_name_len: u32,
    pub salt_len: u32,
    pub root_digest_len: u32,
    pub flags: u32,
    pub reserved: [u8; 60usize],
}
#[test]
fn bindgen_test_layout_AvbHashtreeDescriptor() {
    const UNINIT: ::core::mem::MaybeUninit<AvbHashtreeDescriptor> =
        ::core::mem::MaybeUninit::uninit();
    let ptr = UNINIT.as_ptr();
    assert_eq!(
        ::core::mem::size_of::<AvbHashtreeDescriptor>(),
        180usize,
        concat!("Size of: ", stringify!(AvbHashtreeDescriptor))
    );
    assert_eq!(
        ::core::mem::align_of::<AvbHashtreeDescriptor>(),
        1usize,
        concat!("Alignment of ", stringify!(AvbHashtreeDescriptor))
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).parent_descriptor) as usize - ptr as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbHashtreeDescriptor),
            "::",
            stringify!(parent_descriptor)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).dm_verity_version) as usize - ptr as usize },
        16usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbHashtreeDescriptor),
            "::",
            stringify!(dm_verity_version)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).image_size) as usize - ptr as usize },
        20usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbHashtreeDescriptor),
            "::",
            stringify!(image_size)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).tree_offset) as usize - ptr as usize },
        28usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbHashtreeDescriptor),
            "::",
            stringify!(tree_offset)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).tree_size) as usize - ptr as usize },
        36usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbHashtreeDescriptor),
            "::",
            stringify!(tree_size)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).data_block_size) as usize - ptr as usize },
        44usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbHashtreeDescriptor),
            "::",
            stringify!(data_block_size)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).hash_block_size) as usize - ptr as usize },
        48usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbHashtreeDescriptor),
            "::",
            stringify!(hash_block_size)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).fec_num_roots) as usize - ptr as usize },
        52usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbHashtreeDescriptor),
            "::",
            stringify!(fec_num_roots)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).fec_offset) as usize - ptr as usize },
        56usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbHashtreeDescriptor),
            "::",
            stringify!(fec_offset)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).fec_size) as usize - ptr as usize },
        64usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbHashtreeDescriptor),
            "::",
            stringify!(fec_size)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).hash_algorithm) as usize - ptr as usize },
        72usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbHashtreeDescriptor),
            "::",
            stringify!(hash_algorithm)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).partition_name_len) as usize - ptr as usize },
        104usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbHashtreeDescriptor),
            "::",
            stringify!(partition_name_len)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).salt_len) as usize - ptr as usize },
        108usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbHashtreeDescriptor),
            "::",
            stringify!(salt_len)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).root_digest_len) as usize - ptr as usize },
        112usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbHashtreeDescriptor),
            "::",
            stringify!(root_digest_len)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).flags) as usize - ptr as usize },
        116usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbHashtreeDescriptor),
            "::",
            stringify!(flags)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).reserved) as usize - ptr as usize },
        120usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbHashtreeDescriptor),
            "::",
            stringify!(reserved)
        )
    );
}
impl Default for AvbHashtreeDescriptor {
    fn default() -> Self {
        let mut s = ::core::mem::MaybeUninit::<Self>::uninit();
        unsafe {
            ::core::ptr::write_bytes(s.as_mut_ptr(), 0, 1);
            s.assume_init()
        }
    }
}
impl AvbKernelCmdlineFlags {
    pub const AVB_KERNEL_CMDLINE_FLAGS_USE_ONLY_IF_HASHTREE_NOT_DISABLED: AvbKernelCmdlineFlags =
        AvbKernelCmdlineFlags(1);
}
impl AvbKernelCmdlineFlags {
    pub const AVB_KERNEL_CMDLINE_FLAGS_USE_ONLY_IF_HASHTREE_DISABLED: AvbKernelCmdlineFlags =
        AvbKernelCmdlineFlags(2);
}
impl ::core::ops::BitOr<AvbKernelCmdlineFlags> for AvbKernelCmdlineFlags {
    type Output = Self;
    #[inline]
    fn bitor(self, other: Self) -> Self {
        AvbKernelCmdlineFlags(self.0 | other.0)
    }
}
impl ::core::ops::BitOrAssign for AvbKernelCmdlineFlags {
    #[inline]
    fn bitor_assign(&mut self, rhs: AvbKernelCmdlineFlags) {
        self.0 |= rhs.0;
    }
}
impl ::core::ops::BitAnd<AvbKernelCmdlineFlags> for AvbKernelCmdlineFlags {
    type Output = Self;
    #[inline]
    fn bitand(self, other: Self) -> Self {
        AvbKernelCmdlineFlags(self.0 & other.0)
    }
}
impl ::core::ops::BitAndAssign for AvbKernelCmdlineFlags {
    #[inline]
    fn bitand_assign(&mut self, rhs: AvbKernelCmdlineFlags) {
        self.0 &= rhs.0;
    }
}
#[repr(transparent)]
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub struct AvbKernelCmdlineFlags(pub core::ffi::c_uint);
#[repr(C, packed)]
#[derive(Debug, Default, Copy, Clone, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct AvbKernelCmdlineDescriptor {
    pub parent_descriptor: AvbDescriptor,
    pub flags: u32,
    pub kernel_cmdline_length: u32,
}
#[test]
fn bindgen_test_layout_AvbKernelCmdlineDescriptor() {
    const UNINIT: ::core::mem::MaybeUninit<AvbKernelCmdlineDescriptor> =
        ::core::mem::MaybeUninit::uninit();
    let ptr = UNINIT.as_ptr();
    assert_eq!(
        ::core::mem::size_of::<AvbKernelCmdlineDescriptor>(),
        24usize,
        concat!("Size of: ", stringify!(AvbKernelCmdlineDescriptor))
    );
    assert_eq!(
        ::core::mem::align_of::<AvbKernelCmdlineDescriptor>(),
        1usize,
        concat!("Alignment of ", stringify!(AvbKernelCmdlineDescriptor))
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).parent_descriptor) as usize - ptr as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbKernelCmdlineDescriptor),
            "::",
            stringify!(parent_descriptor)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).flags) as usize - ptr as usize },
        16usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbKernelCmdlineDescriptor),
            "::",
            stringify!(flags)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).kernel_cmdline_length) as usize - ptr as usize },
        20usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbKernelCmdlineDescriptor),
            "::",
            stringify!(kernel_cmdline_length)
        )
    );
}
#[repr(u32)]
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub enum AvbIOResult {
    AVB_IO_RESULT_OK = 0,
    AVB_IO_RESULT_ERROR_OOM = 1,
    AVB_IO_RESULT_ERROR_IO = 2,
    AVB_IO_RESULT_ERROR_NO_SUCH_PARTITION = 3,
    AVB_IO_RESULT_ERROR_RANGE_OUTSIDE_PARTITION = 4,
    AVB_IO_RESULT_ERROR_NO_SUCH_VALUE = 5,
    AVB_IO_RESULT_ERROR_INVALID_VALUE_SIZE = 6,
    AVB_IO_RESULT_ERROR_INSUFFICIENT_SPACE = 7,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct AvbABOps {
    _unused: [u8; 0],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct AvbOps {
    pub user_data: *mut core::ffi::c_void,
    pub ab_ops: *mut AvbABOps,
    pub cert_ops: *mut AvbCertOps,
    pub read_from_partition: ::core::option::Option<
        unsafe extern "C" fn(
            ops: *mut AvbOps,
            partition: *const core::ffi::c_char,
            offset: i64,
            num_bytes: usize,
            buffer: *mut core::ffi::c_void,
            out_num_read: *mut usize,
        ) -> AvbIOResult,
    >,
    pub get_preloaded_partition: ::core::option::Option<
        unsafe extern "C" fn(
            ops: *mut AvbOps,
            partition: *const core::ffi::c_char,
            num_bytes: usize,
            out_pointer: *mut *mut u8,
            out_num_bytes_preloaded: *mut usize,
        ) -> AvbIOResult,
    >,
    pub write_to_partition: ::core::option::Option<
        unsafe extern "C" fn(
            ops: *mut AvbOps,
            partition: *const core::ffi::c_char,
            offset: i64,
            num_bytes: usize,
            buffer: *const core::ffi::c_void,
        ) -> AvbIOResult,
    >,
    pub validate_vbmeta_public_key: ::core::option::Option<
        unsafe extern "C" fn(
            ops: *mut AvbOps,
            public_key_data: *const u8,
            public_key_length: usize,
            public_key_metadata: *const u8,
            public_key_metadata_length: usize,
            out_is_trusted: *mut bool,
        ) -> AvbIOResult,
    >,
    pub read_rollback_index: ::core::option::Option<
        unsafe extern "C" fn(
            ops: *mut AvbOps,
            rollback_index_location: usize,
            out_rollback_index: *mut u64,
        ) -> AvbIOResult,
    >,
    pub write_rollback_index: ::core::option::Option<
        unsafe extern "C" fn(
            ops: *mut AvbOps,
            rollback_index_location: usize,
            rollback_index: u64,
        ) -> AvbIOResult,
    >,
    pub read_is_device_unlocked: ::core::option::Option<
        unsafe extern "C" fn(ops: *mut AvbOps, out_is_unlocked: *mut bool) -> AvbIOResult,
    >,
    pub get_unique_guid_for_partition: ::core::option::Option<
        unsafe extern "C" fn(
            ops: *mut AvbOps,
            partition: *const core::ffi::c_char,
            guid_buf: *mut core::ffi::c_char,
            guid_buf_size: usize,
        ) -> AvbIOResult,
    >,
    pub get_size_of_partition: ::core::option::Option<
        unsafe extern "C" fn(
            ops: *mut AvbOps,
            partition: *const core::ffi::c_char,
            out_size_num_bytes: *mut u64,
        ) -> AvbIOResult,
    >,
    pub read_persistent_value: ::core::option::Option<
        unsafe extern "C" fn(
            ops: *mut AvbOps,
            name: *const core::ffi::c_char,
            buffer_size: usize,
            out_buffer: *mut u8,
            out_num_bytes_read: *mut usize,
        ) -> AvbIOResult,
    >,
    pub write_persistent_value: ::core::option::Option<
        unsafe extern "C" fn(
            ops: *mut AvbOps,
            name: *const core::ffi::c_char,
            value_size: usize,
            value: *const u8,
        ) -> AvbIOResult,
    >,
    pub validate_public_key_for_partition: ::core::option::Option<
        unsafe extern "C" fn(
            ops: *mut AvbOps,
            partition: *const core::ffi::c_char,
            public_key_data: *const u8,
            public_key_length: usize,
            public_key_metadata: *const u8,
            public_key_metadata_length: usize,
            out_is_trusted: *mut bool,
            out_rollback_index_location: *mut u32,
        ) -> AvbIOResult,
    >,
}
#[test]
fn bindgen_test_layout_AvbOps() {
    const UNINIT: ::core::mem::MaybeUninit<AvbOps> = ::core::mem::MaybeUninit::uninit();
    let ptr = UNINIT.as_ptr();
    assert_eq!(
        ::core::mem::size_of::<AvbOps>(),
        120usize,
        concat!("Size of: ", stringify!(AvbOps))
    );
    assert_eq!(
        ::core::mem::align_of::<AvbOps>(),
        8usize,
        concat!("Alignment of ", stringify!(AvbOps))
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).user_data) as usize - ptr as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbOps),
            "::",
            stringify!(user_data)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).ab_ops) as usize - ptr as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbOps),
            "::",
            stringify!(ab_ops)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).cert_ops) as usize - ptr as usize },
        16usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbOps),
            "::",
            stringify!(cert_ops)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).read_from_partition) as usize - ptr as usize },
        24usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbOps),
            "::",
            stringify!(read_from_partition)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).get_preloaded_partition) as usize - ptr as usize },
        32usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbOps),
            "::",
            stringify!(get_preloaded_partition)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).write_to_partition) as usize - ptr as usize },
        40usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbOps),
            "::",
            stringify!(write_to_partition)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).validate_vbmeta_public_key) as usize - ptr as usize },
        48usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbOps),
            "::",
            stringify!(validate_vbmeta_public_key)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).read_rollback_index) as usize - ptr as usize },
        56usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbOps),
            "::",
            stringify!(read_rollback_index)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).write_rollback_index) as usize - ptr as usize },
        64usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbOps),
            "::",
            stringify!(write_rollback_index)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).read_is_device_unlocked) as usize - ptr as usize },
        72usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbOps),
            "::",
            stringify!(read_is_device_unlocked)
        )
    );
    assert_eq!(
        unsafe {
            ::core::ptr::addr_of!((*ptr).get_unique_guid_for_partition) as usize - ptr as usize
        },
        80usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbOps),
            "::",
            stringify!(get_unique_guid_for_partition)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).get_size_of_partition) as usize - ptr as usize },
        88usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbOps),
            "::",
            stringify!(get_size_of_partition)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).read_persistent_value) as usize - ptr as usize },
        96usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbOps),
            "::",
            stringify!(read_persistent_value)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).write_persistent_value) as usize - ptr as usize },
        104usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbOps),
            "::",
            stringify!(write_persistent_value)
        )
    );
    assert_eq!(
        unsafe {
            ::core::ptr::addr_of!((*ptr).validate_public_key_for_partition) as usize - ptr as usize
        },
        112usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbOps),
            "::",
            stringify!(validate_public_key_for_partition)
        )
    );
}
impl Default for AvbOps {
    fn default() -> Self {
        let mut s = ::core::mem::MaybeUninit::<Self>::uninit();
        unsafe {
            ::core::ptr::write_bytes(s.as_mut_ptr(), 0, 1);
            s.assume_init()
        }
    }
}
#[repr(C, packed)]
#[derive(Debug, Default, Copy, Clone, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct AvbPropertyDescriptor {
    pub parent_descriptor: AvbDescriptor,
    pub key_num_bytes: u64,
    pub value_num_bytes: u64,
}
#[test]
fn bindgen_test_layout_AvbPropertyDescriptor() {
    const UNINIT: ::core::mem::MaybeUninit<AvbPropertyDescriptor> =
        ::core::mem::MaybeUninit::uninit();
    let ptr = UNINIT.as_ptr();
    assert_eq!(
        ::core::mem::size_of::<AvbPropertyDescriptor>(),
        32usize,
        concat!("Size of: ", stringify!(AvbPropertyDescriptor))
    );
    assert_eq!(
        ::core::mem::align_of::<AvbPropertyDescriptor>(),
        1usize,
        concat!("Alignment of ", stringify!(AvbPropertyDescriptor))
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).parent_descriptor) as usize - ptr as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbPropertyDescriptor),
            "::",
            stringify!(parent_descriptor)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).key_num_bytes) as usize - ptr as usize },
        16usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbPropertyDescriptor),
            "::",
            stringify!(key_num_bytes)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).value_num_bytes) as usize - ptr as usize },
        24usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbPropertyDescriptor),
            "::",
            stringify!(value_num_bytes)
        )
    );
}
impl AvbPropertyDescriptor {
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < size_of::<Self>() {
            return Err(anyhow!("Invalid descriptor"));
        }
        let mut dest = Self::new_zeroed();
        Self::ref_from_bytes(&data[0..size_of::<Self>()])
            .map_err(|_| anyhow!("Invalid descriptor"))?
            .to_host_byte_order(&mut dest);
        Ok(dest)
    }

    pub fn to_be_bytes(&self) -> Vec<u8> {
        let mut dest = Self::new_zeroed();
        self.to_host_byte_order(&mut dest);
        dest.as_bytes().to_vec()
    }

    fn to_host_byte_order(&self, dest: &mut Self) {
        dest.parent_descriptor.tag = self.parent_descriptor.tag.to_be();
        dest.parent_descriptor.num_bytes_following = self.parent_descriptor.num_bytes_following.to_be();
        dest.key_num_bytes = self.key_num_bytes.to_be();
        dest.value_num_bytes = self.value_num_bytes.to_be();
    }
}
#[derive(Clone)]
pub struct AvbPropertyDescriptorInfo {
    pub descriptor: AvbPropertyDescriptor,
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}
impl AvbPropertyDescriptorInfo {
    fn from_bytes(data: &[u8]) -> Result<Self> {
        let descriptor = AvbPropertyDescriptor::from_bytes(data)?;
        let mut offset = size_of::<AvbPropertyDescriptor>();
        let key = data[offset..offset + descriptor.key_num_bytes as usize].to_vec();
        offset += descriptor.key_num_bytes as usize + 1;
        let value = data[offset..offset + descriptor.value_num_bytes as usize].to_vec();
        Ok(Self { descriptor, key, value })
    }

    pub fn fix_header(&mut self) {
        self.descriptor.key_num_bytes = self.key.len() as u64;
        self.descriptor.value_num_bytes = self.value.len() as u64;
        self.descriptor.parent_descriptor.num_bytes_following = (size_of::<AvbPropertyDescriptor>() - AVB_DESCRIPTOR_SIZE + self.key.len() + 1 + self.value.len() + 1) as u64;
        self.descriptor.parent_descriptor.num_bytes_following += padding_size(self.descriptor.parent_descriptor.num_bytes_following as usize, DESCRIPTOR_ALIGN) as u64;
    }

    pub fn to_be_bytes(&self) -> Vec<u8> {
        let mut data = self.descriptor.to_be_bytes();
        data.extend_from_slice(self.key.as_bytes());
        data.push(0);
        data.extend_from_slice(self.value.as_bytes());
        data.push(0);
        pad_right(&mut data, DESCRIPTOR_ALIGN);
        data
    }
}
impl AvbVBMetaImageFlags {
    pub const AVB_VBMETA_IMAGE_FLAGS_HASHTREE_DISABLED: AvbVBMetaImageFlags =
        AvbVBMetaImageFlags(1);
}
impl AvbVBMetaImageFlags {
    pub const AVB_VBMETA_IMAGE_FLAGS_VERIFICATION_DISABLED: AvbVBMetaImageFlags =
        AvbVBMetaImageFlags(2);
}
impl ::core::ops::BitOr<AvbVBMetaImageFlags> for AvbVBMetaImageFlags {
    type Output = Self;
    #[inline]
    fn bitor(self, other: Self) -> Self {
        AvbVBMetaImageFlags(self.0 | other.0)
    }
}
impl ::core::ops::BitOrAssign for AvbVBMetaImageFlags {
    #[inline]
    fn bitor_assign(&mut self, rhs: AvbVBMetaImageFlags) {
        self.0 |= rhs.0;
    }
}
impl ::core::ops::BitAnd<AvbVBMetaImageFlags> for AvbVBMetaImageFlags {
    type Output = Self;
    #[inline]
    fn bitand(self, other: Self) -> Self {
        AvbVBMetaImageFlags(self.0 & other.0)
    }
}
impl ::core::ops::BitAndAssign for AvbVBMetaImageFlags {
    #[inline]
    fn bitand_assign(&mut self, rhs: AvbVBMetaImageFlags) {
        self.0 &= rhs.0;
    }
}
#[repr(transparent)]
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub struct AvbVBMetaImageFlags(pub core::ffi::c_uint);
#[repr(C, packed)]
#[derive(Debug, Copy, Clone, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct AvbVBMetaImageHeader {
    pub magic: [u8; 4usize],
    pub required_libavb_version_major: u32,
    pub required_libavb_version_minor: u32,
    pub authentication_data_block_size: u64,
    pub auxiliary_data_block_size: u64,
    pub algorithm_type: u32,
    pub hash_offset: u64,
    pub hash_size: u64,
    pub signature_offset: u64,
    pub signature_size: u64,
    pub public_key_offset: u64,
    pub public_key_size: u64,
    pub public_key_metadata_offset: u64,
    pub public_key_metadata_size: u64,
    pub descriptors_offset: u64,
    pub descriptors_size: u64,
    pub rollback_index: u64,
    pub flags: u32,
    pub rollback_index_location: u32,
    pub release_string: [u8; 48usize],
    pub reserved: [u8; 80usize],
}
#[test]
fn bindgen_test_layout_AvbVBMetaImageHeader() {
    const UNINIT: ::core::mem::MaybeUninit<AvbVBMetaImageHeader> =
        ::core::mem::MaybeUninit::uninit();
    let ptr = UNINIT.as_ptr();
    assert_eq!(
        ::core::mem::size_of::<AvbVBMetaImageHeader>(),
        256usize,
        concat!("Size of: ", stringify!(AvbVBMetaImageHeader))
    );
    assert_eq!(
        ::core::mem::align_of::<AvbVBMetaImageHeader>(),
        1usize,
        concat!("Alignment of ", stringify!(AvbVBMetaImageHeader))
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).magic) as usize - ptr as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbVBMetaImageHeader),
            "::",
            stringify!(magic)
        )
    );
    assert_eq!(
        unsafe {
            ::core::ptr::addr_of!((*ptr).required_libavb_version_major) as usize - ptr as usize
        },
        4usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbVBMetaImageHeader),
            "::",
            stringify!(required_libavb_version_major)
        )
    );
    assert_eq!(
        unsafe {
            ::core::ptr::addr_of!((*ptr).required_libavb_version_minor) as usize - ptr as usize
        },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbVBMetaImageHeader),
            "::",
            stringify!(required_libavb_version_minor)
        )
    );
    assert_eq!(
        unsafe {
            ::core::ptr::addr_of!((*ptr).authentication_data_block_size) as usize - ptr as usize
        },
        12usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbVBMetaImageHeader),
            "::",
            stringify!(authentication_data_block_size)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).auxiliary_data_block_size) as usize - ptr as usize },
        20usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbVBMetaImageHeader),
            "::",
            stringify!(auxiliary_data_block_size)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).algorithm_type) as usize - ptr as usize },
        28usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbVBMetaImageHeader),
            "::",
            stringify!(algorithm_type)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).hash_offset) as usize - ptr as usize },
        32usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbVBMetaImageHeader),
            "::",
            stringify!(hash_offset)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).hash_size) as usize - ptr as usize },
        40usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbVBMetaImageHeader),
            "::",
            stringify!(hash_size)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).signature_offset) as usize - ptr as usize },
        48usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbVBMetaImageHeader),
            "::",
            stringify!(signature_offset)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).signature_size) as usize - ptr as usize },
        56usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbVBMetaImageHeader),
            "::",
            stringify!(signature_size)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).public_key_offset) as usize - ptr as usize },
        64usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbVBMetaImageHeader),
            "::",
            stringify!(public_key_offset)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).public_key_size) as usize - ptr as usize },
        72usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbVBMetaImageHeader),
            "::",
            stringify!(public_key_size)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).public_key_metadata_offset) as usize - ptr as usize },
        80usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbVBMetaImageHeader),
            "::",
            stringify!(public_key_metadata_offset)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).public_key_metadata_size) as usize - ptr as usize },
        88usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbVBMetaImageHeader),
            "::",
            stringify!(public_key_metadata_size)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).descriptors_offset) as usize - ptr as usize },
        96usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbVBMetaImageHeader),
            "::",
            stringify!(descriptors_offset)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).descriptors_size) as usize - ptr as usize },
        104usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbVBMetaImageHeader),
            "::",
            stringify!(descriptors_size)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).rollback_index) as usize - ptr as usize },
        112usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbVBMetaImageHeader),
            "::",
            stringify!(rollback_index)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).flags) as usize - ptr as usize },
        120usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbVBMetaImageHeader),
            "::",
            stringify!(flags)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).rollback_index_location) as usize - ptr as usize },
        124usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbVBMetaImageHeader),
            "::",
            stringify!(rollback_index_location)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).release_string) as usize - ptr as usize },
        128usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbVBMetaImageHeader),
            "::",
            stringify!(release_string)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).reserved) as usize - ptr as usize },
        176usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbVBMetaImageHeader),
            "::",
            stringify!(reserved)
        )
    );
}
impl AvbVBMetaImageHeader {
    pub fn from_bytes(src: &[u8]) -> Result<Self> {
        if src.len() < HEADER_SIZE {
            return Err(anyhow!("Invalid VBMeta image header"));
        }
        let mut dest = Self::new_zeroed();
        Self::to_host_byte_order(unsafe { &*(src.as_ptr() as *const Self) }, &mut dest);
        Ok(dest)
    }

    pub fn to_be_bytes(&self) -> Vec<u8> {
        let mut dest = Self::new_zeroed();
        self.to_host_byte_order(&mut dest);
        dest.as_bytes().to_vec()
    }

    fn to_host_byte_order(&self, dest: &mut Self) {
        dest.magic = self.magic;
        dest.required_libavb_version_major = self.required_libavb_version_major.to_be();
        dest.required_libavb_version_minor = self.required_libavb_version_minor.to_be();
        dest.authentication_data_block_size = self.authentication_data_block_size.to_be();
        dest.auxiliary_data_block_size = self.auxiliary_data_block_size.to_be();
        dest.algorithm_type = self.algorithm_type.to_be();
        dest.hash_offset = self.hash_offset.to_be();
        dest.hash_size = self.hash_size.to_be();
        dest.signature_offset = self.signature_offset.to_be();
        dest.signature_size = self.signature_size.to_be();
        dest.public_key_offset = self.public_key_offset.to_be();
        dest.public_key_size = self.public_key_size.to_be();
        dest.public_key_metadata_offset = self.public_key_metadata_offset.to_be();
        dest.public_key_metadata_size = self.public_key_metadata_size.to_be();
        dest.descriptors_offset = self.descriptors_offset.to_be();
        dest.descriptors_size = self.descriptors_size.to_be();
        dest.rollback_index = self.rollback_index.to_be();
        dest.flags = self.flags.to_be();
        dest.rollback_index_location = self.rollback_index_location.to_be();
        dest.release_string = self.release_string;
    }

    pub fn get_hash<'a>(&'a self, authentication_data: &'a [u8]) -> Result<&'a [u8]> {
        authentication_data
            .get(self.hash_offset as usize..self.hash_offset as usize + self.hash_size as usize)
            .ok_or(anyhow!("Invalid hash offset"))
    }

    pub fn get_signature<'a>(&'a self, authentication_data: &'a [u8]) -> Result<&'a [u8]> {
        authentication_data
            .get(self.signature_offset as usize..self.signature_offset as usize + self.signature_size as usize)
            .ok_or(anyhow!("Invalid signature offset"))
    }

    pub fn get_public_key<'a>(&'a self, auxiliary_data: &'a [u8]) -> Result<&'a [u8]> {
        auxiliary_data
            .get(self.public_key_offset as usize..self.public_key_offset as usize + self.public_key_size as usize)
            .ok_or(anyhow!("Invalid public key offset"))
    }

    pub fn get_public_key_metadata<'a>(&'a self, auxiliary_data: &'a [u8]) -> Result<&'a [u8]> {
        auxiliary_data
            .get(self.public_key_metadata_offset as usize..self.public_key_metadata_offset as usize + self.public_key_metadata_size as usize)
            .ok_or(anyhow!("Invalid public key metadata offset"))
    }

    pub fn get_descriptors<'a>(&'a self, auxiliary_data: &'a [u8]) -> Result<&'a [u8]> {
        auxiliary_data
            .get(self.descriptors_offset as usize..self.descriptors_offset as usize + self.descriptors_size as usize)
            .ok_or(anyhow!("Invalid descriptors offset"))
    }
}
impl Default for AvbVBMetaImageHeader {
    fn default() -> Self {
        let mut s = ::core::mem::MaybeUninit::<Self>::uninit();
        unsafe {
            ::core::ptr::write_bytes(s.as_mut_ptr(), 0, 1);
            s.assume_init()
        }
    }
}
#[repr(u32)]
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub enum AvbVBMetaVerifyResult {
    AVB_VBMETA_VERIFY_RESULT_OK = 0,
    AVB_VBMETA_VERIFY_RESULT_OK_NOT_SIGNED = 1,
    AVB_VBMETA_VERIFY_RESULT_INVALID_VBMETA_HEADER = 2,
    AVB_VBMETA_VERIFY_RESULT_UNSUPPORTED_VERSION = 3,
    AVB_VBMETA_VERIFY_RESULT_HASH_MISMATCH = 4,
    AVB_VBMETA_VERIFY_RESULT_SIGNATURE_MISMATCH = 5,
}
#[repr(u32)]
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub enum AvbSlotVerifyResult {
    AVB_SLOT_VERIFY_RESULT_OK = 0,
    AVB_SLOT_VERIFY_RESULT_ERROR_OOM = 1,
    AVB_SLOT_VERIFY_RESULT_ERROR_IO = 2,
    AVB_SLOT_VERIFY_RESULT_ERROR_VERIFICATION = 3,
    AVB_SLOT_VERIFY_RESULT_ERROR_ROLLBACK_INDEX = 4,
    AVB_SLOT_VERIFY_RESULT_ERROR_PUBLIC_KEY_REJECTED = 5,
    AVB_SLOT_VERIFY_RESULT_ERROR_INVALID_METADATA = 6,
    AVB_SLOT_VERIFY_RESULT_ERROR_UNSUPPORTED_VERSION = 7,
    AVB_SLOT_VERIFY_RESULT_ERROR_INVALID_ARGUMENT = 8,
}
#[repr(u32)]
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub enum AvbHashtreeErrorMode {
    AVB_HASHTREE_ERROR_MODE_RESTART_AND_INVALIDATE = 0,
    AVB_HASHTREE_ERROR_MODE_RESTART = 1,
    AVB_HASHTREE_ERROR_MODE_EIO = 2,
    AVB_HASHTREE_ERROR_MODE_LOGGING = 3,
    AVB_HASHTREE_ERROR_MODE_MANAGED_RESTART_AND_EIO = 4,
    AVB_HASHTREE_ERROR_MODE_PANIC = 5,
}
impl AvbSlotVerifyFlags {
    pub const AVB_SLOT_VERIFY_FLAGS_NONE: AvbSlotVerifyFlags = AvbSlotVerifyFlags(0);
}
impl AvbSlotVerifyFlags {
    pub const AVB_SLOT_VERIFY_FLAGS_ALLOW_VERIFICATION_ERROR: AvbSlotVerifyFlags =
        AvbSlotVerifyFlags(1);
}
impl AvbSlotVerifyFlags {
    pub const AVB_SLOT_VERIFY_FLAGS_RESTART_CAUSED_BY_HASHTREE_CORRUPTION: AvbSlotVerifyFlags =
        AvbSlotVerifyFlags(2);
}
impl AvbSlotVerifyFlags {
    pub const AVB_SLOT_VERIFY_FLAGS_NO_VBMETA_PARTITION: AvbSlotVerifyFlags = AvbSlotVerifyFlags(4);
}
impl ::core::ops::BitOr<AvbSlotVerifyFlags> for AvbSlotVerifyFlags {
    type Output = Self;
    #[inline]
    fn bitor(self, other: Self) -> Self {
        AvbSlotVerifyFlags(self.0 | other.0)
    }
}
impl ::core::ops::BitOrAssign for AvbSlotVerifyFlags {
    #[inline]
    fn bitor_assign(&mut self, rhs: AvbSlotVerifyFlags) {
        self.0 |= rhs.0;
    }
}
impl ::core::ops::BitAnd<AvbSlotVerifyFlags> for AvbSlotVerifyFlags {
    type Output = Self;
    #[inline]
    fn bitand(self, other: Self) -> Self {
        AvbSlotVerifyFlags(self.0 & other.0)
    }
}
impl ::core::ops::BitAndAssign for AvbSlotVerifyFlags {
    #[inline]
    fn bitand_assign(&mut self, rhs: AvbSlotVerifyFlags) {
        self.0 &= rhs.0;
    }
}
#[repr(transparent)]
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub struct AvbSlotVerifyFlags(pub core::ffi::c_uint);
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct AvbPartitionData {
    pub partition_name: *mut core::ffi::c_char,
    pub data: *mut u8,
    pub data_size: usize,
    pub preloaded: bool,
    pub verify_result: AvbSlotVerifyResult,
    pub digest: *mut u8,
    pub digest_size: usize,
    pub digest_type: AvbDigestType,
}
#[test]
fn bindgen_test_layout_AvbPartitionData() {
    const UNINIT: ::core::mem::MaybeUninit<AvbPartitionData> = ::core::mem::MaybeUninit::uninit();
    let ptr = UNINIT.as_ptr();
    assert_eq!(
        ::core::mem::size_of::<AvbPartitionData>(),
        56usize,
        concat!("Size of: ", stringify!(AvbPartitionData))
    );
    assert_eq!(
        ::core::mem::align_of::<AvbPartitionData>(),
        8usize,
        concat!("Alignment of ", stringify!(AvbPartitionData))
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).partition_name) as usize - ptr as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbPartitionData),
            "::",
            stringify!(partition_name)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).data) as usize - ptr as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbPartitionData),
            "::",
            stringify!(data)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).data_size) as usize - ptr as usize },
        16usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbPartitionData),
            "::",
            stringify!(data_size)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).preloaded) as usize - ptr as usize },
        24usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbPartitionData),
            "::",
            stringify!(preloaded)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).verify_result) as usize - ptr as usize },
        28usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbPartitionData),
            "::",
            stringify!(verify_result)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).digest) as usize - ptr as usize },
        32usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbPartitionData),
            "::",
            stringify!(digest)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).digest_size) as usize - ptr as usize },
        40usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbPartitionData),
            "::",
            stringify!(digest_size)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).digest_type) as usize - ptr as usize },
        48usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbPartitionData),
            "::",
            stringify!(digest_type)
        )
    );
}
impl Default for AvbPartitionData {
    fn default() -> Self {
        let mut s = ::core::mem::MaybeUninit::<Self>::uninit();
        unsafe {
            ::core::ptr::write_bytes(s.as_mut_ptr(), 0, 1);
            s.assume_init()
        }
    }
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct AvbVBMetaData {
    pub partition_name: *mut core::ffi::c_char,
    pub vbmeta_data: *mut u8,
    pub vbmeta_size: usize,
    pub verify_result: AvbVBMetaVerifyResult,
}
#[test]
fn bindgen_test_layout_AvbVBMetaData() {
    const UNINIT: ::core::mem::MaybeUninit<AvbVBMetaData> = ::core::mem::MaybeUninit::uninit();
    let ptr = UNINIT.as_ptr();
    assert_eq!(
        ::core::mem::size_of::<AvbVBMetaData>(),
        32usize,
        concat!("Size of: ", stringify!(AvbVBMetaData))
    );
    assert_eq!(
        ::core::mem::align_of::<AvbVBMetaData>(),
        8usize,
        concat!("Alignment of ", stringify!(AvbVBMetaData))
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).partition_name) as usize - ptr as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbVBMetaData),
            "::",
            stringify!(partition_name)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).vbmeta_data) as usize - ptr as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbVBMetaData),
            "::",
            stringify!(vbmeta_data)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).vbmeta_size) as usize - ptr as usize },
        16usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbVBMetaData),
            "::",
            stringify!(vbmeta_size)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).verify_result) as usize - ptr as usize },
        24usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbVBMetaData),
            "::",
            stringify!(verify_result)
        )
    );
}
impl Default for AvbVBMetaData {
    fn default() -> Self {
        let mut s = ::core::mem::MaybeUninit::<Self>::uninit();
        unsafe {
            ::core::ptr::write_bytes(s.as_mut_ptr(), 0, 1);
            s.assume_init()
        }
    }
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct AvbSlotVerifyData {
    pub ab_suffix: *mut core::ffi::c_char,
    pub vbmeta_images: *mut AvbVBMetaData,
    pub num_vbmeta_images: usize,
    pub loaded_partitions: *mut AvbPartitionData,
    pub num_loaded_partitions: usize,
    pub cmdline: *mut core::ffi::c_char,
    pub rollback_indexes: [u64; 32usize],
    pub resolved_hashtree_error_mode: AvbHashtreeErrorMode,
}
#[test]
fn bindgen_test_layout_AvbSlotVerifyData() {
    const UNINIT: ::core::mem::MaybeUninit<AvbSlotVerifyData> = ::core::mem::MaybeUninit::uninit();
    let ptr = UNINIT.as_ptr();
    assert_eq!(
        ::core::mem::size_of::<AvbSlotVerifyData>(),
        312usize,
        concat!("Size of: ", stringify!(AvbSlotVerifyData))
    );
    assert_eq!(
        ::core::mem::align_of::<AvbSlotVerifyData>(),
        8usize,
        concat!("Alignment of ", stringify!(AvbSlotVerifyData))
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).ab_suffix) as usize - ptr as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbSlotVerifyData),
            "::",
            stringify!(ab_suffix)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).vbmeta_images) as usize - ptr as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbSlotVerifyData),
            "::",
            stringify!(vbmeta_images)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).num_vbmeta_images) as usize - ptr as usize },
        16usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbSlotVerifyData),
            "::",
            stringify!(num_vbmeta_images)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).loaded_partitions) as usize - ptr as usize },
        24usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbSlotVerifyData),
            "::",
            stringify!(loaded_partitions)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).num_loaded_partitions) as usize - ptr as usize },
        32usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbSlotVerifyData),
            "::",
            stringify!(num_loaded_partitions)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).cmdline) as usize - ptr as usize },
        40usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbSlotVerifyData),
            "::",
            stringify!(cmdline)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).rollback_indexes) as usize - ptr as usize },
        48usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbSlotVerifyData),
            "::",
            stringify!(rollback_indexes)
        )
    );
    assert_eq!(
        unsafe {
            ::core::ptr::addr_of!((*ptr).resolved_hashtree_error_mode) as usize - ptr as usize
        },
        304usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbSlotVerifyData),
            "::",
            stringify!(resolved_hashtree_error_mode)
        )
    );
}
impl Default for AvbSlotVerifyData {
    fn default() -> Self {
        let mut s = ::core::mem::MaybeUninit::<Self>::uninit();
        unsafe {
            ::core::ptr::write_bytes(s.as_mut_ptr(), 0, 1);
            s.assume_init()
        }
    }
}
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct AvbCertPermanentAttributes {
    pub version: u32,
    pub product_root_public_key: [u8; 1032usize],
    pub product_id: [u8; 16usize],
}
#[test]
fn bindgen_test_layout_AvbCertPermanentAttributes() {
    const UNINIT: ::core::mem::MaybeUninit<AvbCertPermanentAttributes> =
        ::core::mem::MaybeUninit::uninit();
    let ptr = UNINIT.as_ptr();
    assert_eq!(
        ::core::mem::size_of::<AvbCertPermanentAttributes>(),
        1052usize,
        concat!("Size of: ", stringify!(AvbCertPermanentAttributes))
    );
    assert_eq!(
        ::core::mem::align_of::<AvbCertPermanentAttributes>(),
        1usize,
        concat!("Alignment of ", stringify!(AvbCertPermanentAttributes))
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).version) as usize - ptr as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbCertPermanentAttributes),
            "::",
            stringify!(version)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).product_root_public_key) as usize - ptr as usize },
        4usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbCertPermanentAttributes),
            "::",
            stringify!(product_root_public_key)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).product_id) as usize - ptr as usize },
        1036usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbCertPermanentAttributes),
            "::",
            stringify!(product_id)
        )
    );
}
impl Default for AvbCertPermanentAttributes {
    fn default() -> Self {
        let mut s = ::core::mem::MaybeUninit::<Self>::uninit();
        unsafe {
            ::core::ptr::write_bytes(s.as_mut_ptr(), 0, 1);
            s.assume_init()
        }
    }
}
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct AvbCertCertificateSignedData {
    pub version: u32,
    pub public_key: [u8; 1032usize],
    pub subject: [u8; 32usize],
    pub usage: [u8; 32usize],
    pub key_version: u64,
}
#[test]
fn bindgen_test_layout_AvbCertCertificateSignedData() {
    const UNINIT: ::core::mem::MaybeUninit<AvbCertCertificateSignedData> =
        ::core::mem::MaybeUninit::uninit();
    let ptr = UNINIT.as_ptr();
    assert_eq!(
        ::core::mem::size_of::<AvbCertCertificateSignedData>(),
        1108usize,
        concat!("Size of: ", stringify!(AvbCertCertificateSignedData))
    );
    assert_eq!(
        ::core::mem::align_of::<AvbCertCertificateSignedData>(),
        1usize,
        concat!("Alignment of ", stringify!(AvbCertCertificateSignedData))
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).version) as usize - ptr as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbCertCertificateSignedData),
            "::",
            stringify!(version)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).public_key) as usize - ptr as usize },
        4usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbCertCertificateSignedData),
            "::",
            stringify!(public_key)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).subject) as usize - ptr as usize },
        1036usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbCertCertificateSignedData),
            "::",
            stringify!(subject)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).usage) as usize - ptr as usize },
        1068usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbCertCertificateSignedData),
            "::",
            stringify!(usage)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).key_version) as usize - ptr as usize },
        1100usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbCertCertificateSignedData),
            "::",
            stringify!(key_version)
        )
    );
}
impl Default for AvbCertCertificateSignedData {
    fn default() -> Self {
        let mut s = ::core::mem::MaybeUninit::<Self>::uninit();
        unsafe {
            ::core::ptr::write_bytes(s.as_mut_ptr(), 0, 1);
            s.assume_init()
        }
    }
}
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct AvbCertCertificate {
    pub signed_data: AvbCertCertificateSignedData,
    pub signature: [u8; 512usize],
}
#[test]
fn bindgen_test_layout_AvbCertCertificate() {
    const UNINIT: ::core::mem::MaybeUninit<AvbCertCertificate> = ::core::mem::MaybeUninit::uninit();
    let ptr = UNINIT.as_ptr();
    assert_eq!(
        ::core::mem::size_of::<AvbCertCertificate>(),
        1620usize,
        concat!("Size of: ", stringify!(AvbCertCertificate))
    );
    assert_eq!(
        ::core::mem::align_of::<AvbCertCertificate>(),
        1usize,
        concat!("Alignment of ", stringify!(AvbCertCertificate))
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).signed_data) as usize - ptr as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbCertCertificate),
            "::",
            stringify!(signed_data)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).signature) as usize - ptr as usize },
        1108usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbCertCertificate),
            "::",
            stringify!(signature)
        )
    );
}
impl Default for AvbCertCertificate {
    fn default() -> Self {
        let mut s = ::core::mem::MaybeUninit::<Self>::uninit();
        unsafe {
            ::core::ptr::write_bytes(s.as_mut_ptr(), 0, 1);
            s.assume_init()
        }
    }
}
#[repr(C, packed)]
#[derive(Debug, Default, Copy, Clone)]
pub struct AvbCertUnlockChallenge {
    pub version: u32,
    pub product_id_hash: [u8; 32usize],
    pub challenge: [u8; 16usize],
}
#[test]
fn bindgen_test_layout_AvbCertUnlockChallenge() {
    const UNINIT: ::core::mem::MaybeUninit<AvbCertUnlockChallenge> =
        ::core::mem::MaybeUninit::uninit();
    let ptr = UNINIT.as_ptr();
    assert_eq!(
        ::core::mem::size_of::<AvbCertUnlockChallenge>(),
        52usize,
        concat!("Size of: ", stringify!(AvbCertUnlockChallenge))
    );
    assert_eq!(
        ::core::mem::align_of::<AvbCertUnlockChallenge>(),
        1usize,
        concat!("Alignment of ", stringify!(AvbCertUnlockChallenge))
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).version) as usize - ptr as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbCertUnlockChallenge),
            "::",
            stringify!(version)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).product_id_hash) as usize - ptr as usize },
        4usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbCertUnlockChallenge),
            "::",
            stringify!(product_id_hash)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).challenge) as usize - ptr as usize },
        36usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbCertUnlockChallenge),
            "::",
            stringify!(challenge)
        )
    );
}
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct AvbCertUnlockCredential {
    pub version: u32,
    pub product_intermediate_key_certificate: AvbCertCertificate,
    pub product_unlock_key_certificate: AvbCertCertificate,
    pub challenge_signature: [u8; 512usize],
}
#[test]
fn bindgen_test_layout_AvbCertUnlockCredential() {
    const UNINIT: ::core::mem::MaybeUninit<AvbCertUnlockCredential> =
        ::core::mem::MaybeUninit::uninit();
    let ptr = UNINIT.as_ptr();
    assert_eq!(
        ::core::mem::size_of::<AvbCertUnlockCredential>(),
        3756usize,
        concat!("Size of: ", stringify!(AvbCertUnlockCredential))
    );
    assert_eq!(
        ::core::mem::align_of::<AvbCertUnlockCredential>(),
        1usize,
        concat!("Alignment of ", stringify!(AvbCertUnlockCredential))
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).version) as usize - ptr as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbCertUnlockCredential),
            "::",
            stringify!(version)
        )
    );
    assert_eq!(
        unsafe {
            ::core::ptr::addr_of!((*ptr).product_intermediate_key_certificate) as usize
                - ptr as usize
        },
        4usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbCertUnlockCredential),
            "::",
            stringify!(product_intermediate_key_certificate)
        )
    );
    assert_eq!(
        unsafe {
            ::core::ptr::addr_of!((*ptr).product_unlock_key_certificate) as usize - ptr as usize
        },
        1624usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbCertUnlockCredential),
            "::",
            stringify!(product_unlock_key_certificate)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).challenge_signature) as usize - ptr as usize },
        3244usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbCertUnlockCredential),
            "::",
            stringify!(challenge_signature)
        )
    );
}
impl Default for AvbCertUnlockCredential {
    fn default() -> Self {
        let mut s = ::core::mem::MaybeUninit::<Self>::uninit();
        unsafe {
            ::core::ptr::write_bytes(s.as_mut_ptr(), 0, 1);
            s.assume_init()
        }
    }
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct AvbCertOps {
    pub ops: *mut AvbOps,
    pub read_permanent_attributes: ::core::option::Option<
        unsafe extern "C" fn(
            cert_ops: *mut AvbCertOps,
            attributes: *mut AvbCertPermanentAttributes,
        ) -> AvbIOResult,
    >,
    pub read_permanent_attributes_hash: ::core::option::Option<
        unsafe extern "C" fn(cert_ops: *mut AvbCertOps, hash: *mut u8) -> AvbIOResult,
    >,
    pub set_key_version: ::core::option::Option<
        unsafe extern "C" fn(
            cert_ops: *mut AvbCertOps,
            rollback_index_location: usize,
            key_version: u64,
        ),
    >,
    pub get_random: ::core::option::Option<
        unsafe extern "C" fn(
            cert_ops: *mut AvbCertOps,
            num_bytes: usize,
            output: *mut u8,
        ) -> AvbIOResult,
    >,
}
#[test]
fn bindgen_test_layout_AvbCertOps() {
    const UNINIT: ::core::mem::MaybeUninit<AvbCertOps> = ::core::mem::MaybeUninit::uninit();
    let ptr = UNINIT.as_ptr();
    assert_eq!(
        ::core::mem::size_of::<AvbCertOps>(),
        40usize,
        concat!("Size of: ", stringify!(AvbCertOps))
    );
    assert_eq!(
        ::core::mem::align_of::<AvbCertOps>(),
        8usize,
        concat!("Alignment of ", stringify!(AvbCertOps))
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).ops) as usize - ptr as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbCertOps),
            "::",
            stringify!(ops)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).read_permanent_attributes) as usize - ptr as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbCertOps),
            "::",
            stringify!(read_permanent_attributes)
        )
    );
    assert_eq!(
        unsafe {
            ::core::ptr::addr_of!((*ptr).read_permanent_attributes_hash) as usize - ptr as usize
        },
        16usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbCertOps),
            "::",
            stringify!(read_permanent_attributes_hash)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).set_key_version) as usize - ptr as usize },
        24usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbCertOps),
            "::",
            stringify!(set_key_version)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).get_random) as usize - ptr as usize },
        32usize,
        concat!(
            "Offset of field: ",
            stringify!(AvbCertOps),
            "::",
            stringify!(get_random)
        )
    );
}
impl Default for AvbCertOps {
    fn default() -> Self {
        let mut s = ::core::mem::MaybeUninit::<Self>::uninit();
        unsafe {
            ::core::ptr::write_bytes(s.as_mut_ptr(), 0, 1);
            s.assume_init()
        }
    }
}

#[derive(Clone)]
pub struct AvbRawDescriptor {
    data: Vec<u8>,
}

impl AvbRawDescriptor {
    fn from_bytes(data: &[u8]) -> Self {
        Self { data: data.to_vec() }
    }
}

#[derive(Clone)]
pub enum AvbDescriptorEnum {
    Hash(AvbHashDescriptorInfo),
    Property(AvbPropertyDescriptorInfo),
    Raw(AvbRawDescriptor),
}

impl AvbDescriptorEnum {
    pub fn to_be_bytes(&self) -> Vec<u8> {
        match self {
            AvbDescriptorEnum::Hash(hash_descriptor) => hash_descriptor.to_be_bytes(),
            AvbDescriptorEnum::Property(property_descriptor) => property_descriptor.to_be_bytes(),
            AvbDescriptorEnum::Raw(raw_descriptor) => raw_descriptor.data.clone(),
        }
    }
}

fn to_fixed_length(val: &BigUint, num_bytes: usize) -> Result<Vec<u8>> {
    let b = val.to_bytes_be();
    if b.len() > num_bytes {
        Err(anyhow!("Too long"))
    } else {
        let mut pad = vec![0; num_bytes - b.len()];
        pad.extend(b);
        Ok(pad)
    }
}

fn convert_to_avb_pubkey(pubkey: &RsaPublicKey) -> Result<Vec<u8>> {
    let num_key_bytes = pubkey.size();

    let modulus_bytes = to_fixed_length(&pubkey.n(), num_key_bytes)?;

    let n_signed = BigInt::from_biguint(num_bigint_dig::Sign::Plus, pubkey.n().clone());
    let r = BigInt::one() << 32;
    let egcd = n_signed.extended_gcd(&r);

    let n0inv = if egcd.0.is_one() {
        let inv = (egcd.1 % &r + &r) % &r;
        let n0_prime = (&r - inv) % &r;
        n0_prime.to_biguint()
    } else {
        None
    };
    let n0inv = match n0inv {
        Some(s) => match s.to_u32() {
            Some(s) => s,
            None => return Err(anyhow!("Failed to calculate n0inv")),
        },
        None => return Err(anyhow!("Failed to calculate n0inv")),
    };
    let mut pubkey_header = AvbRSAPublicKeyHeader::new_zeroed();
    pubkey_header.key_num_bits = num_key_bytes as u32 * 8;
    pubkey_header.n0inv = n0inv;

    let two = BigUint::from(2u8);
    let exponent = BigUint::from(2 * (num_key_bytes * 8));

    let rr = two.modpow(&exponent, pubkey.n());
    let rr_bytes = to_fixed_length(&rr, num_key_bytes)?;

    let mut pubkey = AvbRSAPublicKey::default();
    pubkey.header = pubkey_header;
    pubkey.modulus = modulus_bytes;
    pubkey.rr = rr_bytes;

    Ok(pubkey.to_be_bytes())
}


#[derive(Clone)]
pub struct VBMeta {
    pub header: AvbVBMetaImageHeader,
    pub authentication_data: Vec<u8>,
    pub auxiliary_data: Vec<u8>,
    pub descriptors: Vec<AvbDescriptorEnum>,
    pub footer: Option<AvbFooter>,
    pub partition_name: Option<String>,
}

impl VBMeta {
    pub fn new(base_header: AvbVBMetaImageHeader, key: Option<RsaPrivateKey>, descriptors: Vec<AvbDescriptorEnum>, original_image_size: Option<usize>) -> Result<Self> {
        let mut header = base_header.clone();

        let algo_type = header.algorithm_type;
        if let Some(key) = &key {
            header.hash_offset = 0;
            header.hash_size = Hasher::digest_size(algo_type)? as u64;
            header.signature_offset = header.hash_size;
            header.signature_size = key.size() as u64;
        } else {
            assert!(algo_type == AvbAlgorithmType::AVB_ALGORITHM_TYPE_NONE as u32);
            header.hash_offset = 0;
            header.hash_size = 0;
            header.signature_offset = 0;
            header.signature_size = 0;
        }
        let pubkey_bytes = if let Some(key) = &key { convert_to_avb_pubkey(&key.to_public_key())? } else { vec![] };

        header.authentication_data_block_size = header.signature_offset + header.signature_size;
        let authentication_pad = vec![0; padding_size(header.authentication_data_block_size as usize, VBMETA_ALIGN)];
        header.authentication_data_block_size += authentication_pad.len() as u64;

        let mut descriptors_data = vec![];
        for descriptor in &descriptors {
            descriptors_data.extend(descriptor.to_be_bytes());
        }
        header.descriptors_offset = 0;
        header.descriptors_size = descriptors_data.len() as u64;
        header.public_key_offset = header.descriptors_offset + header.descriptors_size;
        header.public_key_size = pubkey_bytes.len() as u64;
        header.public_key_metadata_offset = header.public_key_offset + header.public_key_size;
        header.public_key_metadata_size = 0;

        let mut auxiliary_data = descriptors_data;
        auxiliary_data.extend(pubkey_bytes);
        pad_right(&mut auxiliary_data, VBMETA_ALIGN);

        header.auxiliary_data_block_size = auxiliary_data.len() as u64;

        let header_bytes = header.to_be_bytes();

        let authentication_data = if let Some(key) = &key {
            // Signature of VBMeta header + Auxiliary data block.
            let (hash, signature) = crate::hasher::sign(key, algo_type, &[&header_bytes[..], &auxiliary_data[..]].concat())?;

            let mut authentication_data: Vec<u8> = hash;
            authentication_data.extend(signature);
            pad_right(&mut authentication_data, VBMETA_ALIGN);
            authentication_data
        } else {
            vec![]
        };
        let (footer, partition_name) = if let Some(original_image_size) = original_image_size {
            let mut footer = AvbFooter::new_zeroed();
            footer.magic.copy_from_slice(&AVB_FOOTER_MAGIC[..4]);
            footer.original_image_size = original_image_size as u64;
            footer.vbmeta_offset = original_image_size as u64;
            footer.vbmeta_size = header_bytes.len() as u64 + authentication_data.len() as u64 + auxiliary_data.len() as u64;
            footer.version_major = 1;
            footer.version_minor = 0;
            let partition_name = Self::find_partition_name(&descriptors);
            (Some(footer), partition_name)
        } else {
            (None, None)
        };

        Ok(Self {
            header,
            authentication_data,
            auxiliary_data,
            descriptors,
            footer,
            partition_name,
        })
    }

    pub fn from_device(f: &mut dyn IoDelegate) -> Result<Self> {
        use std::io::SeekFrom;

        let footer = AvbFooter::from_file(f)?;

        let header_offset = footer.as_ref().map_or(0, |f| f.vbmeta_offset);
        f.seek(SeekFrom::Start(header_offset))?;
        let mut header_buf = vec![0; HEADER_SIZE];
        f.read_exact(&mut header_buf)?;

        let header = AvbVBMetaImageHeader::from_bytes(&header_buf)?;

        if &header.magic == &AVB_MAGIC[0..4] {
            info!("Magic ok.");
        } else {
            return Err(anyhow!("VBMeta magic is not valid."));
        }

        // VBMeta = AvbVBMetaImageHeader + Authentication data + Auxiliary data
        // Authentication data = hash + signature
        // Auxiliary data = descriptor + public key + publib key metadata
        let authentication_data_offset = header_offset as usize + HEADER_SIZE;
        let auxiliary_data_offset = authentication_data_offset + header.authentication_data_block_size as usize;

        f.seek(SeekFrom::Start(authentication_data_offset as u64))?;
        let mut authentication_data = vec![0; header.authentication_data_block_size as usize];
        f.read_exact(&mut authentication_data)?;

        f.seek(SeekFrom::Start(auxiliary_data_offset as u64))?;
        let mut auxiliary_data = vec![0; header.auxiliary_data_block_size as usize];
        f.read_exact(&mut auxiliary_data)?;

        let descriptors_data = header.get_descriptors(&auxiliary_data)?;

        let original_image = if let Some(footer) = &footer {
            f.seek(SeekFrom::Start(0))?;
            let mut image_data = vec![0; footer.original_image_size as usize];
            f.read_exact(&mut image_data)?;
            Some((footer.original_image_size, image_data))
        } else {
            None
        };

        let mut offset = 0;
        let mut descriptors = vec![];
        while offset < descriptors_data.len() {
            let descriptor = AvbDescriptor::from_bytes(&descriptors_data[offset..offset + AVB_DESCRIPTOR_SIZE])?;

            let tag = descriptor.tag;
            let num_bytes_following = descriptor.num_bytes_following as usize;

            let descriptor_data = &descriptors_data[offset..offset + AVB_DESCRIPTOR_SIZE + num_bytes_following as usize];

            if tag == AvbDescriptorTag::AVB_DESCRIPTOR_TAG_HASH as u64 {
                let hash_descriptor_info = AvbHashDescriptorInfo::from_bytes(descriptor_data)?;
                descriptors.push(AvbDescriptorEnum::Hash(hash_descriptor_info));
            } else if tag == AvbDescriptorTag::AVB_DESCRIPTOR_TAG_PROPERTY as u64 {
                let property_descriptor_info = AvbPropertyDescriptorInfo::from_bytes(descriptor_data)?;
                descriptors.push(AvbDescriptorEnum::Property(property_descriptor_info));
            } else {
                let avb_raw_descriptor = AvbRawDescriptor::from_bytes(descriptor_data);
                descriptors.push(AvbDescriptorEnum::Raw(avb_raw_descriptor));
            }

            offset += AVB_DESCRIPTOR_SIZE + num_bytes_following as usize;
        }
        let partition_name = if footer.is_some() { Self::find_partition_name(&descriptors) } else { None };
        Ok(Self {
            header,
            authentication_data,
            auxiliary_data,
            descriptors,
            footer,
            partition_name,
        })
    }

    fn find_partition_name(descriptors: &Vec<AvbDescriptorEnum>) -> Option<String> {
        descriptors.iter().find_map(|descriptor| {
            if let AvbDescriptorEnum::Hash(hash_descriptor_info) = descriptor {
                return Some(String::from_utf8(hash_descriptor_info.partition_name.to_vec()).ok()?);
            }
            None
        })
    }

    pub fn to_be_bytes(&self) -> Vec<u8> {
        let mut vbmeta_bytes = vec![];
        vbmeta_bytes.extend_from_slice(&self.header.to_be_bytes());
        vbmeta_bytes.extend_from_slice(&self.authentication_data);
        vbmeta_bytes.extend_from_slice(&self.auxiliary_data);
        vbmeta_bytes
    }

    pub fn get_partition_name(f: &mut dyn IoDelegate) -> Result<String> {
        let vbmeta = Self::from_device(f)?;
        vbmeta.partition_name.ok_or(anyhow!("Partition name not found"))
    }

    pub fn calculate_vbmeta_hash(&self) -> Result<Vec<u8>> {
        let mut hasher = Hasher::new(self.header.algorithm_type)?;
        hasher.update(&self.header.to_be_bytes());
        hasher.update(&self.auxiliary_data);
        Ok(hasher.finalize())
    }

    pub fn get_public_key(&self) -> Result<RsaPublicKey> {
        let public_key = self.header.get_public_key(&self.auxiliary_data)?;

        let public_key = AvbRSAPublicKey::from_bytes(public_key)?;

        let n = BigUint::from_bytes_be(&public_key.modulus);
        let e = BigUint::from(PUBLIC_EXPONENT);
        Ok(RsaPublicKey::new(n, e)?)
    }

    pub fn verify_vbmeta_signature(&self) -> Result<bool> {
        let hash = self.calculate_vbmeta_hash()?;

        let verifying_key = VerifyingKey::<rsa::sha2::Sha256>::new(self.get_public_key()?);

        let signature = self.header.get_signature(&self.authentication_data)?;
        let signature = rsa::pkcs1v15::Signature::try_from(signature)?;
        Ok(match verifying_key.verify_prehash(&hash, &signature) {
            Ok(_) => {
                info!("Signature verification Ok");
                true
            }
            Err(e) => {
                info!("Signature verification Failed: {e}");
                false
            }
        })
    }
}
