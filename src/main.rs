mod bindings;
mod testkey;
mod hasher;

use std::io::Read;
use std::io::Seek;
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::os::unix::io::AsRawFd;

use anyhow::Context;
use clap::Subcommand;
use num_bigint_dig::BigInt;
use num_bigint_dig::ExtendedGcd;
use num_traits::ToPrimitive;
use num_traits::identities::One;
use rsa::BigUint;
use rsa::RsaPrivateKey;
use rsa::RsaPublicKey;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs1v15::VerifyingKey;
use rsa::sha2::Sha256;
use rsa::signature::SignatureEncoding;
use rsa::signature::hazmat::PrehashSigner;
use rsa::signature::hazmat::PrehashVerifier;
use rsa::traits::PublicKeyParts;

use log::{debug, error, info, warn};
use clap::Parser;
use anyhow::Result;
use anyhow::anyhow;

#[macro_use]
extern crate nix;

use crate::bindings::AvbDescriptorTag;
use crate::bindings::AvbFooter;
use crate::bindings::AvbRSAPublicKeyHeader;
use crate::bindings::AvbVBMetaImageHeader;
use crate::bindings::AVB_FOOTER_MAGIC;
use crate::bindings::AVB_MAGIC;
use crate::bindings::AvbDescriptor;
use crate::bindings::AvbHashDescriptor;

use crate::hasher::Hasher;
use crate::testkey::TESTKEY_2048;
use crate::testkey::TESTKEY_4096;

fn avb_vbmeta_image_header_to_host_byte_order(
    src: &AvbVBMetaImageHeader,
    dest: &mut AvbVBMetaImageHeader,
) {
    dest.magic = src.magic;
    dest.required_libavb_version_major = src.required_libavb_version_major.to_be();
    dest.required_libavb_version_minor = src.required_libavb_version_minor.to_be();
    dest.authentication_data_block_size = src.authentication_data_block_size.to_be();
    dest.auxiliary_data_block_size = src.auxiliary_data_block_size.to_be();
    dest.algorithm_type = src.algorithm_type.to_be();
    dest.hash_offset = src.hash_offset.to_be();
    dest.hash_size = src.hash_size.to_be();
    dest.signature_offset = src.signature_offset.to_be();
    dest.signature_size = src.signature_size.to_be();
    dest.public_key_offset = src.public_key_offset.to_be();
    dest.public_key_size = src.public_key_size.to_be();
    dest.public_key_metadata_offset = src.public_key_metadata_offset.to_be();
    dest.public_key_metadata_size = src.public_key_metadata_size.to_be();
    dest.descriptors_offset = src.descriptors_offset.to_be();
    dest.descriptors_size = src.descriptors_size.to_be();
    dest.rollback_index = src.rollback_index.to_be();
    dest.flags = src.flags.to_be();
    dest.rollback_index_location = src.rollback_index_location.to_be();
    dest.release_string = src.release_string;
}

fn avb_footer_to_host_byte_order(src: &AvbFooter, dest: &mut AvbFooter) {
    dest.magic = src.magic;
    dest.version_major = src.version_major.to_be();
    dest.version_minor = src.version_minor.to_be();
    dest.original_image_size = src.original_image_size.to_be();
    dest.vbmeta_offset = src.vbmeta_offset.to_be();
    dest.vbmeta_size = src.vbmeta_size.to_be();
}

fn avb_hash_descriptor_to_host_byte_order(src: &AvbHashDescriptor, dest: &mut AvbHashDescriptor) {
    dest.parent_descriptor.tag = src.parent_descriptor.tag.to_be();
    dest.parent_descriptor.num_bytes_following = src.parent_descriptor.num_bytes_following.to_be();
    dest.image_size = src.image_size.to_be();
    dest.hash_algorithm = src.hash_algorithm;
    dest.partition_name_len = src.partition_name_len.to_be();
    dest.salt_len = src.salt_len.to_be();
    dest.digest_len = src.digest_len.to_be();
    dest.flags = src.flags.to_be();
    dest.reserved = src.reserved;
}

fn avb_pubkey_to_host_byte_order(src: &AvbRSAPublicKeyHeader, dest: &mut AvbRSAPublicKeyHeader) {
    dest.key_num_bits = src.key_num_bits.to_be();
    dest.n0inv = src.n0inv.to_be();
}

fn hex(bin: &[u8]) -> String {
    bin.iter().map(|b| format!("{:02x}", b)).collect()
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

fn pad_size(len: usize, align: usize) -> usize {
    (len + align - 1) / align * align - len
}

fn pad_right(val: &mut Vec<u8>, align: usize) {
    val.extend(vec![0; pad_size(val.len(), align)]);
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
    let mut pubkey_header = AvbRSAPublicKeyHeader::default();
    pubkey_header.key_num_bits = num_key_bytes as u32 * 8;
    pubkey_header.n0inv = n0inv;

    let two = BigUint::from(2u8);
    let exponent = BigUint::from(2 * (num_key_bytes * 8));

    let rr = two.modpow(&exponent, pubkey.n());
    let rr_bytes = to_fixed_length(&rr, num_key_bytes)?;

    let mut pubkey_bytes = vec![];
    let mut pubkey_header_dest = AvbRSAPublicKeyHeader::default();
    avb_pubkey_to_host_byte_order(&pubkey_header, &mut pubkey_header_dest);
    pubkey_bytes.extend_from_slice(unsafe {
        std::slice::from_raw_parts(
            &pubkey_header_dest as *const AvbRSAPublicKeyHeader as *const u8,
            std::mem::size_of::<AvbRSAPublicKeyHeader>(),
        )
    });
    pubkey_bytes.extend(modulus_bytes);
    pubkey_bytes.extend(rr_bytes);

    Ok(pubkey_bytes)
}

enum KeyBits {
    Key2048,
    Key4096,
}

struct ParsedHeaders {
    key_num_bits: KeyBits,
    header: AvbVBMetaImageHeader,
    original_image_size: Option<usize>,
    image_data: Option<Vec<u8>>,
    vbmeta_hashes_match: bool,
    vbmeta_signatures_match: bool,
    parititon_sizes_match: bool,
    partition_hashes_match: bool,
    new_descriptors_data: Vec<u8>,
    algo_type: u32,
}

fn get_key_bits(key_bits: KeyBits) -> usize {
    match key_bits {
        KeyBits::Key2048 => 2048,
        KeyBits::Key4096 => 4096,
    }
}

fn get_key_bytes(key_bits: KeyBits) -> usize {
    get_key_bits(key_bits) / 8
}

fn parse_vbmeta(mut f: std::fs::File, filesize: usize) -> Result<ParsedHeaders> {
    let (header_offset, original_image_size) = if filesize >= FOOTER_SIZE {
        f.seek(std::io::SeekFrom::End(-(FOOTER_SIZE as i64)))?;
        let mut buf = vec![0; FOOTER_SIZE];
        f.read_exact(&mut buf)?;
        let footer = buf.as_ptr() as *const AvbFooter;
        let mut footer_dest = AvbFooter::default();
        avb_footer_to_host_byte_order(unsafe { &*footer }, &mut footer_dest);
        if footer_dest.magic == AVB_FOOTER_MAGIC[0..4] {
            let vbmeta_size = footer_dest.vbmeta_size;
            info!("VBMeta size in footer: {}", vbmeta_size);
            (footer_dest.vbmeta_offset, Some(footer_dest.original_image_size))
        } else {
            (0, None)
        }
    } else {
        (0, None)
    };
    info!("VBMeta header offset: {} original image size: {:?}", header_offset, original_image_size);

    f.seek(std::io::SeekFrom::Start(header_offset))?;
    let mut header_buf = vec![0; HEADER_SIZE];
    f.read_exact(&mut header_buf)?;

    let header_src = unsafe { &*(header_buf.as_ptr() as *const AvbVBMetaImageHeader) };
    let mut header = AvbVBMetaImageHeader::default();
    avb_vbmeta_image_header_to_host_byte_order(header_src, &mut header);

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
    let auxiliary_data_size = header.auxiliary_data_block_size as usize;

    f.seek(std::io::SeekFrom::Start(authentication_data_offset as u64))?;
    let mut authentication_data = vec![0; auxiliary_data_size];
    f.read_exact(&mut authentication_data)?;

    f.seek(std::io::SeekFrom::Start(auxiliary_data_offset as u64))?;
    let mut auxiliary_data = vec![0; auxiliary_data_size];
    f.read_exact(&mut auxiliary_data)?;

    let mut message = header_buf[0..HEADER_SIZE].to_vec();
    message.extend(&auxiliary_data);

    let algo_type = header.algorithm_type;
    let mut hasher = Hasher::new(algo_type)?;
    hasher.update(&message);
    let hash_calc = hasher.finalize();

    let hash = &authentication_data[header.hash_offset as usize..header.hash_offset as usize + header.hash_size as usize];

    let vbmeta_hashes_match = hash_calc == hash;
    if hash_calc == hash {
        info!("Hashes of VBMeta matched");
    }

    let public_key_data = &auxiliary_data[header.public_key_offset as usize..header.public_key_offset as usize + header.public_key_size as usize];
    let public_key_header = public_key_data.as_ptr() as *const AvbRSAPublicKeyHeader;
    let pubkey_header_size = std::mem::size_of::<AvbRSAPublicKeyHeader>();
    let num_bits = unsafe { (*public_key_header).key_num_bits.to_be() };
    let modulus = &public_key_data[pubkey_header_size..pubkey_header_size + num_bits as usize / 8];

    let n = BigUint::from_bytes_be(modulus);
    let e = BigUint::from(PUBLIC_EXPONENT);
    let pubkey = RsaPublicKey::new(n, e)?;

    let verifying_key = VerifyingKey::<rsa::sha2::Sha256>::new(pubkey);

    let sig_value = &authentication_data[header.signature_offset as usize..header.signature_offset as usize + header.signature_size as usize];
    let signature = rsa::pkcs1v15::Signature::try_from(sig_value)?;
    let vbmeta_signatures_match = match verifying_key.verify_prehash(hash, &signature) {
        Ok(_) => {
            info!("Signature verification Ok");
            true
        }
        Err(e) => {
            info!("Signature verification Failed: {e}");
            false
        }
    };
    let key_bits = if num_bits == 2048 {
        KeyBits::Key2048
    } else if num_bits == 4096 {
        KeyBits::Key4096
    } else {
        return Err(anyhow!("Unknown rsa key size: {num_bits}"));
    };

    let descriptors_data = &auxiliary_data[header.descriptors_offset as usize..header.descriptors_offset as usize + header.descriptors_size as usize];

    let original_image = if let Some(original_image_size) = original_image_size {
        f.seek(std::io::SeekFrom::Start(0))?;
        let mut image_data = vec![0; original_image_size as usize];
        f.read_exact(&mut image_data)?;
        Some((original_image_size, image_data))
    } else {
        None
    };

    let mut partition_hashes_match = false;
    let mut parititon_sizes_match = false;
    let mut pos = 0;
    let mut new_descriptors_data = vec![];
    while pos < descriptors_data.len() {
        let descriptor_header = (&descriptors_data[pos..]).as_ptr() as *const AvbDescriptor;
        let descriptor_header_size = std::mem::size_of::<AvbDescriptor>();
        let tag = unsafe { (*descriptor_header).tag.to_be() };
        let num_bytes_following = unsafe { (*descriptor_header).num_bytes_following.to_be() };
        info!("Descriptor tag: {} num_bytes_following: {}", tag, num_bytes_following);
        
        if tag == AvbDescriptorTag::AVB_DESCRIPTOR_TAG_HASH as u64 {
            let hash_descriptor =
            unsafe { &*(descriptors_data.as_ptr().add(pos) as *const AvbHashDescriptor) };
            let hash_descriptor_size = std::mem::size_of::<AvbHashDescriptor>();
            pos += hash_descriptor_size;
            let mut hash_dest = AvbHashDescriptor::default();
            avb_hash_descriptor_to_host_byte_order(hash_descriptor, &mut hash_dest);
            if hash_descriptor_size
            + hash_dest.partition_name_len as usize
            + hash_dest.salt_len as usize
            + hash_dest.digest_len as usize
            != descriptor_header_size + num_bytes_following as usize
            {
                return Err(anyhow!("Invalid hash descriptor"));
            }
            let partition_name =
            &descriptors_data[pos..pos + hash_dest.partition_name_len as usize];
            pos += hash_dest.partition_name_len as usize;
            let salt = &descriptors_data[pos..pos + hash_dest.salt_len as usize];
            pos += hash_dest.salt_len as usize;
            let digest = &descriptors_data[pos..pos + hash_dest.digest_len as usize];
            pos += hash_dest.digest_len as usize;
            let algo_name = String::from_utf8(hash_dest.hash_algorithm.to_vec())?
            .trim_end_matches('\0')
            .to_string();
            debug!("Hash descriptor information:");
            debug!("Algorithm: {}", algo_name);
            debug!("Partition name: {}", String::from_utf8(partition_name.to_vec())?
            .trim_end_matches('\0')
            .to_string()
        );
        debug!("Salt  : {}", hex(salt));
        debug!("Digest: {}", hex(digest));
        
        let hash_partition_calc = match original_image {
            Some(( original_image_size, ref image_data )) => {
                let mut hasher = Hasher::new_by_name(&algo_name)?;
                hasher.update(&salt);
                hasher.update(&image_data);
                let hash_partition_calc = hasher.finalize();
                info!("New partition hash: {}", hex(&hash_partition_calc));
                if hash_partition_calc == digest {
                    info!("Partition hashes match");
                    partition_hashes_match = true;
                } else {
                    info!("Hashes did not match");
                }
                // Fix up it because many(?) boot modification tools don't fix this. They only patch original_image_size on AvbFooter.
                if hash_dest.image_size != original_image_size {
                    info!("Partition sizes mismatch in hash descriptor. Fix it.");
                    hash_dest.image_size = original_image_size;
                } else {
                    info!("Partition sizes match");
                    parititon_sizes_match = true;
                }
                
                hash_partition_calc
            },
            _ => {
                // Hash descriptors in vbmeta.
                return Err(anyhow!("Not supported now"));
            }
        };
        
        let mut new_hash_desc = unsafe { std::mem::zeroed::<AvbHashDescriptor>() };
        avb_hash_descriptor_to_host_byte_order(&hash_dest, &mut new_hash_desc);
        new_descriptors_data.extend_from_slice(unsafe {
            std::slice::from_raw_parts(
                &new_hash_desc as *const AvbHashDescriptor as *const u8,
                hash_descriptor_size,
            )
        });
        new_descriptors_data.extend_from_slice(partition_name);
        new_descriptors_data.extend_from_slice(salt);
        new_descriptors_data.extend_from_slice(&hash_partition_calc);
    } else {
        new_descriptors_data.extend_from_slice(
            &descriptors_data[pos..pos + descriptor_header_size + num_bytes_following as usize],
        );
        pos += descriptor_header_size + num_bytes_following as usize;
    }
}
    Ok(ParsedHeaders {
        key_num_bits: key_bits,
        header: header,
        original_image_size: original_image.as_ref().map_or_else(|| None, |f| Some(f.0 as usize)),
        image_data: original_image.map_or_else(|| None, |f| Some(f.1)),
        vbmeta_hashes_match,
        vbmeta_signatures_match,
        partition_hashes_match,
        parititon_sizes_match,
        new_descriptors_data,
        algo_type,
    })
}

struct GeneratedHeaders {
    vbmeta_bytes: Vec<u8>,
    footer: Option<AvbFooter>,
}

fn generate_new_header(header: &AvbVBMetaImageHeader, new_descriptors_data: Vec<u8>, algo_type: u32, key: &RsaPrivateKey, original_image_size: Option<usize>) -> Result<GeneratedHeaders> {
    let pubkey_bytes = convert_to_avb_pubkey(&key.to_public_key())?;
    let signing_key = SigningKey::<Sha256>::new(key.clone());
    let mut new_header = header.clone();

    new_header.hash_offset = 0;
    new_header.hash_size = Hasher::digest_size(algo_type)? as u64;
    new_header.signature_offset = new_header.hash_size;
    new_header.signature_size = key.size() as u64;

    new_header.authentication_data_block_size = new_header.signature_offset + new_header.signature_size;
    new_header.authentication_data_block_size += pad_size(new_header.authentication_data_block_size as usize, VBMETA_ALIGN) as u64;

    new_header.descriptors_offset = 0;
    new_header.descriptors_size = new_descriptors_data.len() as u64;
    new_header.public_key_offset = new_header.descriptors_offset + new_header.descriptors_size;
    new_header.public_key_size = pubkey_bytes.len() as u64;
    new_header.public_key_metadata_offset = new_header.public_key_offset + new_header.public_key_size;
    new_header.public_key_metadata_size = 0;

    new_header.auxiliary_data_block_size = new_header.public_key_metadata_offset + new_header.public_key_metadata_size;
    let auxiliary_pad = vec![0; pad_size(new_header.auxiliary_data_block_size as usize, VBMETA_ALIGN)];
    new_header.auxiliary_data_block_size += auxiliary_pad.len() as u64;

    let mut new_header_dest = unsafe { std::mem::zeroed::<AvbVBMetaImageHeader>() };
    avb_vbmeta_image_header_to_host_byte_order(&new_header, &mut new_header_dest);

    let mut vbmeta_header_bytes = vec![];
    vbmeta_header_bytes.extend_from_slice(unsafe {
        std::slice::from_raw_parts(
            &new_header_dest as *const AvbVBMetaImageHeader as *const u8,
            std::mem::size_of::<AvbVBMetaImageHeader>(),
        )
    });
    // Signature target is VBMeta header + Auxiliary data block.
    let algo_type = new_header.algorithm_type;
    let mut hasher = Hasher::new(algo_type)?;
    hasher.update(&vbmeta_header_bytes);
    hasher.update(&new_descriptors_data);
    hasher.update(&pubkey_bytes);
    hasher.update(&auxiliary_pad);
    let new_hash = hasher.finalize();
    let new_signature = signing_key.sign_prehash(&new_hash)?.to_bytes();

    let mut vbmeta_bytes = vbmeta_header_bytes;
    vbmeta_bytes.extend(new_hash);
    vbmeta_bytes.extend(new_signature);
    pad_right(&mut vbmeta_bytes, VBMETA_ALIGN);
    vbmeta_bytes.extend(new_descriptors_data);
    vbmeta_bytes.extend(pubkey_bytes);
    vbmeta_bytes.extend(auxiliary_pad);

    let footer = if let Some(original_image_size) = original_image_size {
        let mut footer = unsafe { std::mem::zeroed::<AvbFooter>() };
        footer.magic.copy_from_slice(&AVB_FOOTER_MAGIC[..4]);
        footer.original_image_size = original_image_size as u64;
        footer.vbmeta_offset = original_image_size as u64;
        footer.vbmeta_size = vbmeta_bytes.len() as u64;
        footer.version_major = 1;
        footer.version_minor = 0;
        let mut footer_dest = unsafe { std::mem::zeroed::<AvbFooter>() };
        avb_footer_to_host_byte_order(&footer, &mut footer_dest);
        Some(footer_dest)
    } else {
        None
    };

    Ok(GeneratedHeaders {
        vbmeta_bytes: vbmeta_bytes,
        footer: footer,
    })
}

#[cfg(target_os = "android")]
unsafe extern "C" {
    fn __system_property_get(name: *const u8, value: *mut u8) -> i32;
}
#[cfg(target_os = "android")]
fn get_prop(name: &str) -> Result<String> {
    let mut value = vec![0u8; 1024];
    let len = unsafe {
        __system_property_get((name.to_string() + "\0").as_ptr(), value.as_mut_ptr())
    } as usize;
    if len == 0 {
        Err(anyhow!("Property {name} not found"))
    } else{
        value.resize(len, 0);
        Ok(String::from_utf8(value)?)
    }
}
#[cfg(not(target_os = "android"))]
fn get_prop(_name: &str) -> String {
    "".to_string()
}

const FOOTER_SIZE: usize = std::mem::size_of::<AvbFooter>();
const HEADER_SIZE: usize = std::mem::size_of::<AvbVBMetaImageHeader>();
const PUBLIC_EXPONENT: u32 = 65537u32;
const VBMETA_ALIGN: usize = 64;

/// Read VBMeta from device or files and patch it.
#[derive(Parser, Debug)]
#[command(version, about, long_about = None, after_help = "Example:
 # Patch current slot boot partition
 testkey-signer patch-device
 # Just verify file
 testkey-signer patch-file boot.img
 # Patch file
 testkey-signer patch-file boot.img bootout.img")]
struct Args {
    #[command(subcommand)]
    command: Commands,
    
    #[arg(short, long)]
    log_level: Option<String>,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Operate on current slot of boot partition.
    PatchDevice {
        /// Confirm to patch device automatically.
        /// Run on interactive mode if not specified with confirmation message before writing to devices.
        #[arg(short = 'y')]
        yes: bool,
    },
    #[command(arg_required_else_help = true)]
    PatchFile { input_filename: String, output_filename: Option<String> },
}

fn main() -> Result<()> {
    let mut args = Args::parse();
    if args.log_level.is_none() {
        args.log_level = Some("info".to_string());
    }
    
    // Default log level is info. Set RUST_LOG=debug for more logs.
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(args.log_level.unwrap())).init();
    
    let (input_filename, is_device) = match &args.command {
        Commands::PatchDevice { .. } => {
            let slot_suffix = get_prop("ro.boot.slot_suffix")?;
            info!("Current slot: {}", slot_suffix.trim_start_matches("_"));
            let boot_dev = format!("/dev/block/by-name/boot{slot_suffix}");
            
            (boot_dev, true)
        },
        Commands::PatchFile { input_filename, .. } => {
            (input_filename.clone(), false)
        }
    };
    
    let f = std::fs::File::open(&input_filename).context(format!("Failed to open input file: {}", input_filename))?;
    let filesize = if is_device {
        const BLKGETSIZE64_CODE: u8 = 0x12; // Defined in linux/fs.h
        const BLKGETSIZE64_SEQ: u8 = 114;
        ioctl_read!(ioctl_blkgetsize64, BLKGETSIZE64_CODE, BLKGETSIZE64_SEQ, u64);
        let mut size64 = 0u64;
        let size64_ptr = &mut size64 as *mut u64;
        
        unsafe {
            ioctl_blkgetsize64(f.as_raw_fd(), size64_ptr)?;
        }
        size64 as usize
    }else{
        std::fs::metadata(&input_filename).context(format!("Failed to get filesize of input file: {}", input_filename))?.size() as usize
    };
    
    info!("Parsing VBMeta for {input_filename}.");
    let parsed = parse_vbmeta(f, filesize)?;
    
    let f = |b| if b { "OK" } else { "NG" };
    info!("VBMeta Hash: {}", f(parsed.vbmeta_hashes_match));
    info!("VBMeta Signature: {}", f(parsed.vbmeta_signatures_match));
    info!("Partition Hash: {}", f(parsed.partition_hashes_match));
    info!("Partition Size: {}", f(parsed.parititon_sizes_match));
    if parsed.vbmeta_hashes_match && parsed.vbmeta_signatures_match && parsed.partition_hashes_match && parsed.parititon_sizes_match {
        info!("Hash and signature are all okay. So no need to re-sign. Exit.");
        return Ok(());
    }
    
    // Re-generate VBMeta structures and sign them.
    info!("Generating new VBMeta");
    let testkey = match parsed.key_num_bits {
        KeyBits::Key2048 => TESTKEY_2048,
        KeyBits::Key4096 => TESTKEY_4096,
    };
    let testkey = RsaPrivateKey::from_pkcs1_pem(String::from_utf8(testkey.to_vec())?.as_str())?;
    
    let new_vbmeta = generate_new_header(&parsed.header, parsed.new_descriptors_data, parsed.algo_type, &testkey, parsed.original_image_size)?;
    
    match args.command {
        Commands::PatchDevice { yes } => {
            info!("Patching device");
            if !yes {
                print!("Really patch partitions? (y/n)");
                std::io::stdout().flush()?;
                let mut input = String::new();
                std::io::stdin().read_line(&mut input)?;
                if input.trim() != "y" {
                    return Ok(());
                }
            }
            
            let Some(footer) = new_vbmeta.footer else {
                return Err(anyhow!("No footer was generated"));
            };

            let mut f = std::fs::OpenOptions::new()
            .write(true)
            .read(true)
            .open(&input_filename)?;

            f.seek(std::io::SeekFrom::Start(footer.vbmeta_offset.to_be()))?;
            f.write_all(&new_vbmeta.vbmeta_bytes)?;
            
            f.seek(std::io::SeekFrom::Start((filesize - FOOTER_SIZE) as u64))?;
            f.write_all(unsafe { std::slice::from_raw_parts(&footer as *const AvbFooter as *const u8, FOOTER_SIZE) })?;

            warn!("Patching done.");
        },
        Commands::PatchFile { input_filename: _, output_filename } => {
            if let Some(output_filename) = output_filename {
                warn!("Writing output file: {output_filename}");
                let mut f = std::fs::File::create(output_filename)?;
                match new_vbmeta.footer {
                    Some(footer) => {
                        f.write_all(&parsed.image_data.expect("No image data was loaded"))?;
                        f.write_all(&new_vbmeta.vbmeta_bytes)?;
                        f.seek(std::io::SeekFrom::Start((filesize - FOOTER_SIZE) as u64))?;
                        f.write_all(unsafe { std::slice::from_raw_parts(&footer as *const AvbFooter as *const u8, FOOTER_SIZE) })?;
                    }
                    None => {
                        f.write_all(&new_vbmeta.vbmeta_bytes)?;
                    }
                }
                warn!("Patching done.");
            }
        }
    }

    Ok(())
}
