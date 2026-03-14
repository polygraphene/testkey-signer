mod bindings;
mod hasher;
mod io_delegate;
mod testkey;

use anyhow::Context;
use io_delegate::Environment;
use io_delegate::IoDelegate;
use io_delegate::RealEnvironment;
use zerocopy::FromZeros;
use zerocopy::IntoBytes;

use std::collections::HashMap;
use std::io::Seek;
use std::io::Write;

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

use log::{debug, info, warn, trace};
use clap::Parser;
use anyhow::Result;
use anyhow::anyhow;

#[macro_use]
extern crate nix;

use crate::bindings::AvbAlgorithmType;
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

struct Partition {
    name: String,
    path: String,
    is_device: bool,
}

const FOOTER_SIZE: usize = std::mem::size_of::<AvbFooter>();
const HEADER_SIZE: usize = std::mem::size_of::<AvbVBMetaImageHeader>();
const AVB_DESCRIPTOR_SIZE: usize = std::mem::size_of::<AvbDescriptor>();
const HASH_DESCRIPTOR_SIZE: usize = std::mem::size_of::<AvbHashDescriptor>();
const PUBLIC_EXPONENT: u32 = 65537u32;
const VBMETA_ALIGN: usize = 64;
const DESCRIPTOR_ALIGN: usize = 8;
const SUPPORTED_PARTITIONS: [&str; 5] = ["boot", "init_boot", "vendor_boot", "dtbo", "recovery"];

fn avb_vbmeta_image_header_to_host_byte_order(src: &AvbVBMetaImageHeader, dest: &mut AvbVBMetaImageHeader) {
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

fn avb_vbmeta_image_header_bytes_to_host_byte_order(src: &[u8], dest: &mut AvbVBMetaImageHeader) -> Result<()> {
    if src.len() < HEADER_SIZE {
        return Err(anyhow!("Invalid vbmeta image header size"));
    }
    let header = unsafe { std::ptr::read(src.as_ptr() as *const AvbVBMetaImageHeader) };
    avb_vbmeta_image_header_to_host_byte_order(&header, dest);
    Ok(())
}

fn avb_footer_to_host_byte_order(src: &AvbFooter, dest: &mut AvbFooter) {
    dest.magic = src.magic;
    dest.version_major = src.version_major.to_be();
    dest.version_minor = src.version_minor.to_be();
    dest.original_image_size = src.original_image_size.to_be();
    dest.vbmeta_offset = src.vbmeta_offset.to_be();
    dest.vbmeta_size = src.vbmeta_size.to_be();
}

fn avb_descriptor_to_host_byte_order(src: &AvbDescriptor, dest: &mut AvbDescriptor) {
    dest.tag = src.tag.to_be();
    dest.num_bytes_following = src.num_bytes_following.to_be();
}

fn avb_descriptor_bytes_to_host_byte_order(src: &[u8], dest: &mut AvbDescriptor) -> Result<()> {
    if src.len() < std::mem::size_of::<AvbDescriptor>() {
        return Err(anyhow!("Invalid descriptor"));
    }
    let src_ptr = src.as_ptr() as *const AvbDescriptor;
    avb_descriptor_to_host_byte_order(unsafe { &*src_ptr }, dest);
    Ok(())
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

fn avb_hash_descriptor_bytes_to_host_byte_order(src: &[u8], dest: &mut AvbHashDescriptor) -> Result<()> {
    if src.len() < std::mem::size_of::<AvbHashDescriptor>() {
        return Err(anyhow!("Invalid descriptor"));
    }
    let src_ptr = src.as_ptr() as *const AvbHashDescriptor;
    avb_hash_descriptor_to_host_byte_order(unsafe { &*src_ptr }, dest);
    Ok(())
}

fn avb_pubkey_to_host_byte_order(src: &AvbRSAPublicKeyHeader, dest: &mut AvbRSAPublicKeyHeader) {
    dest.key_num_bits = src.key_num_bits.to_be();
    dest.n0inv = src.n0inv.to_be();
}

fn hex(bin: &[u8]) -> String {
    bin.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hexdump(bin: &[u8]) -> String {
    let mut result = String::new();
    for (i, chunk) in bin.chunks(16).enumerate() {
        result += &format!("{:04x}: ", i * 16);
        for b in chunk {
            result += &format!("{:02x} ", b);
        }
        result += " | ";
        for b in chunk {
            if *b >= 32 && *b <= 126 {
                result += &format!("{}", *b as char);
            } else {
                result += ".";
            }
        }
        result += "\n";
    }
    result
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
    let mut pubkey_header = AvbRSAPublicKeyHeader::new_zeroed();
    pubkey_header.key_num_bits = num_key_bytes as u32 * 8;
    pubkey_header.n0inv = n0inv;

    let two = BigUint::from(2u8);
    let exponent = BigUint::from(2 * (num_key_bytes * 8));

    let rr = two.modpow(&exponent, pubkey.n());
    let rr_bytes = to_fixed_length(&rr, num_key_bytes)?;

    let mut pubkey_bytes = vec![];
    let mut pubkey_header_dest = AvbRSAPublicKeyHeader::new_zeroed();
    avb_pubkey_to_host_byte_order(&pubkey_header, &mut pubkey_header_dest);
    pubkey_bytes.extend_from_slice(unsafe { std::slice::from_raw_parts(&pubkey_header_dest as *const AvbRSAPublicKeyHeader as *const u8, std::mem::size_of::<AvbRSAPublicKeyHeader>()) });
    pubkey_bytes.extend(modulus_bytes);
    pubkey_bytes.extend(rr_bytes);

    Ok(pubkey_bytes)
}

enum KeyBits {
    Key2048,
    Key4096,
}

struct ParsedHeaders {
    key_num_bits: Option<KeyBits>,
    header: AvbVBMetaImageHeader,
    original_image_size: Option<usize>,
    image_data: Option<Vec<u8>>,
    vbmeta_hashes_match: Option<bool>,
    vbmeta_signatures_match: Option<bool>,
    parititon_sizes_match: bool,
    partition_hashes_match: bool,
    new_descriptors_data: Vec<u8>,
    parent_vbmeta_hash_descriptor: Option<Vec<u8>>,
}

impl ParsedHeaders {
    fn is_valid(&self) -> bool {
        self.vbmeta_hashes_match.unwrap_or(false) && self.vbmeta_signatures_match.unwrap_or(false) && self.parititon_sizes_match && self.partition_hashes_match
    }

    fn print_result(&self) {
        let f = |b| if let Some(b) = b { if b { "OK" } else { "NG" } } else { "N/A" };
        let g = |b| if b { "OK" } else { "NG" };
        info!("VBMeta Hash: {}", f(self.vbmeta_hashes_match));
        info!("VBMeta Signature: {}", f(self.vbmeta_signatures_match));
        info!("Partition Hash: {}", g(self.partition_hashes_match));
        info!("Partition Size: {}", g(self.parititon_sizes_match));
    }
}

fn get_key_bits(key_bits: KeyBits) -> usize {
    match key_bits {
        KeyBits::Key2048 => 2048,
        KeyBits::Key4096 => 4096,
    }
}

#[allow(dead_code)]
fn get_key_bytes(key_bits: KeyBits) -> usize {
    get_key_bits(key_bits) / 8
}

fn parse_vbmeta(f: &mut dyn IoDelegate, filesize: usize, is_vbmeta: bool, replace_hash_descriptors: Option<&HashMap<String, Vec<u8>>>) -> Result<ParsedHeaders> {
    let (header_offset, original_image_size) = if !is_vbmeta {
        if filesize >= FOOTER_SIZE {
            f.seek(std::io::SeekFrom::End(-(FOOTER_SIZE as i64)))?;
            let mut buf = vec![0; FOOTER_SIZE];
            f.read_exact(&mut buf)?;
            let footer = buf.as_ptr() as *const AvbFooter;
            let mut footer_dest = AvbFooter::new_zeroed();
            avb_footer_to_host_byte_order(unsafe { &*footer }, &mut footer_dest);
            if footer_dest.magic == AVB_FOOTER_MAGIC[0..4] {
                let vbmeta_size = footer_dest.vbmeta_size;
                info!("VBMeta size in footer: {}", vbmeta_size);
                (footer_dest.vbmeta_offset, Some(footer_dest.original_image_size))
            } else {
                return Err(anyhow!("VBMeta footer not found: Invalid magic."));
            }
        } else {
            return Err(anyhow!("VBMeta footer not found: Too small."));
        }
    } else {
        (0, None)
    };
    info!("VBMeta header offset: {} original image size: {:?}", header_offset, original_image_size);

    f.seek(std::io::SeekFrom::Start(header_offset))?;
    let mut header_buf = vec![0; HEADER_SIZE];
    f.read_exact(&mut header_buf)?;

    let mut header = AvbVBMetaImageHeader::new_zeroed();
    avb_vbmeta_image_header_bytes_to_host_byte_order(&header_buf, &mut header)?;

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
    let (vbmeta_hashes_match, vbmeta_signatures_match, key_bits) = if algo_type == AvbAlgorithmType::AVB_ALGORITHM_TYPE_NONE as u32 {
        // Non chained partition. No verification for hashes or signatures.
        (None, None, None)
    } else {
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
        (Some(vbmeta_hashes_match), Some(vbmeta_signatures_match), Some(key_bits))
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
    let mut parent_vbmeta_hash_descriptor = None;
    while pos < descriptors_data.len() {
        let mut descriptor = AvbDescriptor::new_zeroed();
        avb_descriptor_bytes_to_host_byte_order(&descriptors_data[pos..pos + AVB_DESCRIPTOR_SIZE], &mut descriptor)?;

        let tag = descriptor.tag;
        let num_bytes_following = descriptor.num_bytes_following as usize;
        info!("Descriptor tag: {} num_bytes_following: {}", tag, num_bytes_following);

        if tag == AvbDescriptorTag::AVB_DESCRIPTOR_TAG_HASH as u64 {
            let mut hash_descriptor = AvbHashDescriptor::new_zeroed();
            if pos + AVB_DESCRIPTOR_SIZE + num_bytes_following > descriptors_data.len() || AVB_DESCRIPTOR_SIZE + num_bytes_following < HASH_DESCRIPTOR_SIZE {
                return Err(anyhow!("Invalid hash descriptor"));
            }
            let mut pos_hash = pos;
            avb_hash_descriptor_bytes_to_host_byte_order(&descriptors_data[pos_hash..pos_hash + AVB_DESCRIPTOR_SIZE + num_bytes_following as usize], &mut hash_descriptor)?;
            pos_hash += HASH_DESCRIPTOR_SIZE;
            if HASH_DESCRIPTOR_SIZE + hash_descriptor.partition_name_len as usize + hash_descriptor.salt_len as usize + hash_descriptor.digest_len as usize
                > AVB_DESCRIPTOR_SIZE + num_bytes_following as usize
            {
                return Err(anyhow!("Invalid hash descriptor"));
            }
            let partition_name = &descriptors_data[pos_hash..pos_hash + hash_descriptor.partition_name_len as usize];
            let partition_name_str = String::from_utf8(partition_name.to_vec())?;
            pos_hash += hash_descriptor.partition_name_len as usize;
            let salt = &descriptors_data[pos_hash..pos_hash + hash_descriptor.salt_len as usize];
            pos_hash += hash_descriptor.salt_len as usize;
            let digest = &descriptors_data[pos_hash..pos_hash + hash_descriptor.digest_len as usize];
            pos_hash += hash_descriptor.digest_len as usize;
            let algo_name = String::from_utf8(hash_descriptor.hash_algorithm.to_vec())?.trim_end_matches('\0').to_string();
            debug!("Hash descriptor information:");
            debug!("Algorithm: {}", algo_name);
            debug!("Partition name: {}", partition_name_str);
            debug!("Salt  : {}", hex(salt));
            debug!("Digest: {}", hex(digest));

            match original_image {
                Some((original_image_size, ref image_data)) => {
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
                    // Fix it up because many(?) boot modification tools don't fix this. They only patch original_image_size on AvbFooter.
                    if hash_descriptor.image_size != original_image_size {
                        info!("Partition sizes mismatch in hash descriptor. Fix it.");
                        hash_descriptor.image_size = original_image_size;
                    } else {
                        info!("Partition sizes match");
                        parititon_sizes_match = true;
                    }

                    let mut new_hash_desc = AvbHashDescriptor::new_zeroed();
                    avb_hash_descriptor_to_host_byte_order(&hash_descriptor, &mut new_hash_desc);
                    new_descriptors_data.extend_from_slice(new_hash_desc.as_bytes());
                    new_descriptors_data.extend_from_slice(partition_name);
                    new_descriptors_data.extend_from_slice(salt);
                    new_descriptors_data.extend_from_slice(&hash_partition_calc);
                    pad_right(&mut new_descriptors_data, DESCRIPTOR_ALIGN);

                    parent_vbmeta_hash_descriptor = Some(new_descriptors_data.clone());
                }
                _ => {
                    if let Some(replace_hash_descriptors) = replace_hash_descriptors {
                        if let Some(new_hash_desc) = replace_hash_descriptors.get(&partition_name_str) {
                            info!("Replacing hash descriptors for {partition_name_str} in vbmeta partition buffer.");
                            trace!("{}", hexdump(new_hash_desc));
                            new_descriptors_data.extend_from_slice(new_hash_desc);
                        }
                    }
                }
            };
        } else {
            new_descriptors_data.extend_from_slice(&descriptors_data[pos..pos + AVB_DESCRIPTOR_SIZE + num_bytes_following as usize]);
        }
        pos += AVB_DESCRIPTOR_SIZE + num_bytes_following as usize;
    }
    trace!("Original descriptors:");
    trace!("{}", hexdump(&descriptors_data));
    trace!("New descriptors:");
    trace!("{}", hexdump(&new_descriptors_data));
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
        parent_vbmeta_hash_descriptor,
    })
}

struct GeneratedHeaders {
    vbmeta_bytes: Vec<u8>,
    footer: Option<AvbFooter>,
}

fn generate_new_header(header: &AvbVBMetaImageHeader, new_descriptors_data: Vec<u8>, key: Option<RsaPrivateKey>, original_image_size: Option<usize>) -> Result<GeneratedHeaders> {
    let mut new_header = header.clone();

    let algo_type = new_header.algorithm_type;
    if let Some(key) = &key {
        new_header.hash_offset = 0;
        new_header.hash_size = Hasher::digest_size(algo_type)? as u64;
        new_header.signature_offset = new_header.hash_size;
        new_header.signature_size = key.size() as u64;
    } else {
        assert!(algo_type == AvbAlgorithmType::AVB_ALGORITHM_TYPE_NONE as u32);
        new_header.hash_offset = 0;
        new_header.hash_size = 0;
        new_header.signature_offset = 0;
        new_header.signature_size = 0;
    }
    let pubkey_bytes = if let Some(key) = &key {
        convert_to_avb_pubkey(&key.to_public_key())?
    } else {
        vec![]
    };

    new_header.authentication_data_block_size = new_header.signature_offset + new_header.signature_size;
    let authentication_pad = vec![0; pad_size(new_header.authentication_data_block_size as usize, VBMETA_ALIGN)];
    new_header.authentication_data_block_size += authentication_pad.len() as u64;

    new_header.descriptors_offset = 0;
    new_header.descriptors_size = new_descriptors_data.len() as u64;
    new_header.public_key_offset = new_header.descriptors_offset + new_header.descriptors_size;
    new_header.public_key_size = pubkey_bytes.len() as u64;
    new_header.public_key_metadata_offset = new_header.public_key_offset + new_header.public_key_size;
    new_header.public_key_metadata_size = 0;

    new_header.auxiliary_data_block_size = new_header.public_key_metadata_offset + new_header.public_key_metadata_size;
    let auxiliary_pad = vec![0; pad_size(new_header.auxiliary_data_block_size as usize, VBMETA_ALIGN)];
    new_header.auxiliary_data_block_size += auxiliary_pad.len() as u64;

    let mut new_header_dest = AvbVBMetaImageHeader::new_zeroed();
    avb_vbmeta_image_header_to_host_byte_order(&new_header, &mut new_header_dest);

    let (new_hash, new_signature) = if let Some(key) = &key {
        // Signature target is VBMeta header + Auxiliary data block.
        let mut hasher = Hasher::new(algo_type)?;
        hasher.update(new_header_dest.as_bytes());
        hasher.update(&new_descriptors_data);
        hasher.update(&pubkey_bytes);
        hasher.update(&auxiliary_pad);
        let new_hash = hasher.finalize();
        let signing_key = SigningKey::<Sha256>::new(key.clone());
        let new_signature = signing_key.sign_prehash(&new_hash)?.to_bytes();
        (new_hash, new_signature.to_vec())
    } else {
        (vec![], vec![])
    };

    let mut vbmeta_bytes = vec![];
    vbmeta_bytes.extend_from_slice(new_header_dest.as_bytes());
    vbmeta_bytes.extend(new_hash);
    vbmeta_bytes.extend(new_signature);
    vbmeta_bytes.extend(authentication_pad);
    vbmeta_bytes.extend(new_descriptors_data);
    vbmeta_bytes.extend(pubkey_bytes);
    vbmeta_bytes.extend(auxiliary_pad);

    let footer = if let Some(original_image_size) = original_image_size {
        let mut footer = AvbFooter::new_zeroed();
        footer.magic.copy_from_slice(&AVB_FOOTER_MAGIC[..4]);
        footer.original_image_size = original_image_size as u64;
        footer.vbmeta_offset = original_image_size as u64;
        footer.vbmeta_size = vbmeta_bytes.len() as u64;
        footer.version_major = 1;
        footer.version_minor = 0;
        let mut footer_dest = AvbFooter::new_zeroed();
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

/// Read VBMeta from device or files and patch it.
#[derive(Parser, Debug)]
#[command(version, about, long_about = None, after_help = "Example:
 # Patch current slot boot partition
 testkey-signer patch-device [--inactive-slot]
 # Just verify file
 testkey-signer patch-single-file boot.img
 # Patch file
 testkey-signer patch-single-file boot.img bootout.img")]
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

        /// Patch inactive slot instead of current slot.
        #[arg(short = 'i')]
        inactive_slot: bool,
    },
    #[command(arg_required_else_help = true)]
    PatchSingleFile { input_filename: String, output_filename: Option<String> },
}

fn main() -> Result<()> {
    // Default log level is info. Set RUST_LOG=debug for more logs.
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    run(Args::parse(), &RealEnvironment)
}

fn run(args: Args, env: &dyn Environment) -> Result<()> {
    match &args.command {
        Commands::PatchDevice { inactive_slot, yes } => {
            return run_patch_device(env, *inactive_slot, *yes);
        }
        Commands::PatchSingleFile { input_filename, output_filename } => {
            return run_patch_single_file(env, input_filename, output_filename);
        }
    };
}

fn run_patch_single_file(env: &dyn Environment, input_filename: &str, output_filename: &Option<String>) -> Result<()> {
    let mut device = env.open_device(input_filename, false, false)?;
    let filesize = device.get_size()?;

    if filesize == 0 {
        return Err(anyhow!("Cannot get filesize of {input_filename}"));
    }

    info!("Parsing VBMeta for {input_filename}.");
    let parsed = parse_vbmeta(device.as_mut(), filesize, false, None)?;

    parsed.print_result();
    if parsed.is_valid() {
        info!("Hash and signature are all okay. So no need to re-sign. Exit.");
        return Ok(());
    }

    let Some(output_filename) = output_filename else {
        info!("No output filename provided. Exit.");
        return Ok(());
    };

    // Re-generate VBMeta structures and sign them.
    info!("Generating new VBMeta");
    let testkey = match parsed.key_num_bits {
        Some(num_bits) => {
            let testkey = match num_bits {
                KeyBits::Key2048 => TESTKEY_2048,
                KeyBits::Key4096 => TESTKEY_4096,
            };
            Some(RsaPrivateKey::from_pkcs1_pem(String::from_utf8(testkey.to_vec())?.as_str())?)
        }
        None => None,
    };

    let new_vbmeta = generate_new_header(&parsed.header, parsed.new_descriptors_data, testkey, parsed.original_image_size)?;

    warn!("Writing output file: {output_filename}");
    let mut f_out = std::fs::File::create(output_filename)?;
    match new_vbmeta.footer {
        Some(footer) => {
            f_out.write_all(&parsed.image_data.expect("No image data was loaded"))?;
            f_out.write_all(&new_vbmeta.vbmeta_bytes)?;
            f_out.seek(std::io::SeekFrom::Start((filesize - FOOTER_SIZE) as u64))?;
            f_out.write_all(unsafe { std::slice::from_raw_parts(&footer as *const AvbFooter as *const u8, FOOTER_SIZE) })?;
        }
        None => {
            f_out.write_all(&new_vbmeta.vbmeta_bytes)?;
        }
    }
    warn!("Patching done.");
    Ok(())
}

fn get_test_key(key_num_bits: Option<KeyBits>) -> Result<Option<RsaPrivateKey>> {
    match key_num_bits {
        Some(key_bits) => {
            let testkey = match key_bits {
                KeyBits::Key2048 => TESTKEY_2048,
                KeyBits::Key4096 => TESTKEY_4096,
            };
            Ok(Some(RsaPrivateKey::from_pkcs1_pem(String::from_utf8(testkey.to_vec())?.as_str())?))
        },
        None => Ok(None),
    }
}

fn run_patch_device(env: &dyn Environment, inactive_slot: bool, yes: bool) -> Result<()> {
    let slot_suffix = env.get_prop("ro.boot.slot_suffix").unwrap_or_default();
    if !slot_suffix.is_empty() {
        info!("Current slot: {}", slot_suffix.trim_start_matches("_"));
    } else {
        info!("Non A/B device detected.");
    }
    let slot_suffix = if inactive_slot {
        match slot_suffix.as_str() {
            "_a" => "_b",
            "_b" => "_a",
            "" => return Err(anyhow!("Can't use --inactive-slot in non A/B device")),
            _ => return Err(anyhow!("Invalid slot name: {slot_suffix}")),
        }
    } else {
        match slot_suffix.as_str() {
            "_a" | "_b" | "" => slot_suffix.as_str(),
            _ => return Err(anyhow!("Invalid slot name: {slot_suffix}")),
        }
    };
    if !slot_suffix.is_empty() {
        info!("Target slot: {}", slot_suffix.trim_start_matches("_"));
    }
    let mut partition_set = HashMap::new();
    for partition in SUPPORTED_PARTITIONS {
        let path = format!("/dev/block/by-name/{partition}{slot_suffix}");
        if env.device_exists(&path, true) {
            partition_set.insert(
                partition.to_string(),
                Partition {
                    name: partition.to_string(),
                    path: path,
                    is_device: true,
                },
            );
        }
    }

    let mut parsed_vbmeta_list = vec![];
    let mut replace_hash_descriptors = HashMap::new();
    for partition in partition_set.values() {
        let mut device = env.open_device(&partition.path, false, false)?;
        let filesize = device.get_size()?;
        if filesize == 0 {
            return Err(anyhow!("Cannot get filesize of {}", partition.path));
        }
        info!("Parsing VBMeta for {}", partition.path);
        let mut parsed = parse_vbmeta(device.as_mut(), filesize, false, None).context(format!("Failed to parse VBMeta for {}", partition.path))?;
        replace_hash_descriptors.insert(partition.name.clone(), parsed.new_descriptors_data.clone());
        parsed_vbmeta_list.push((partition, parsed));
    }

    let vbmeta_device = format!("/dev/block/by-name/vbmeta{slot_suffix}");
    let mut device = env.open_device(&vbmeta_device, true, false)?;
    let filesize = device.get_size()?;

    if filesize == 0 {
        return Err(anyhow!("Cannot get filesize of {vbmeta_device}"));
    }

    info!("Parsing VBMeta for {vbmeta_device}.");
    let parsed = parse_vbmeta(device.as_mut(), filesize, true, Some(&replace_hash_descriptors)).context(format!("Failed to parse VBMeta for {vbmeta_device}"))?;

    parsed.print_result();
    if parsed.is_valid() {
        info!("Hash and signature are all okay. So no need to re-sign. Exit.");
        return Ok(());
    }
    info!("Patching device");
    if !yes {
        print!("Really patch partitions? (y/n)");
        std::io::stdout().flush()?;
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if input.trim() != "y" {
            println!("Aborted.");
            return Ok(());
        }
    }

    // Re-generate VBMeta structures and sign them.
    info!("Generating new VBMeta");
    let testkey = get_test_key(parsed.key_num_bits)?;

    let new_vbmeta = generate_new_header(&parsed.header, parsed.new_descriptors_data, testkey, parsed.original_image_size)?;

    let mut device_write = env.open_device(&vbmeta_device, true, true)?;

    device_write.write_all(&new_vbmeta.vbmeta_bytes)?;

    warn!("Successfully patched {vbmeta_device}");

    for (partition, parsed) in parsed_vbmeta_list.into_iter() {
        info!("Patching {}", partition.path);
        let testkey = get_test_key(parsed.key_num_bits)?;
        let new_vbmeta = generate_new_header(&parsed.header, parsed.new_descriptors_data, testkey, parsed.original_image_size)?;
        let Some(footer) = new_vbmeta.footer else {
            return Err(anyhow!("No footer was generated"));
        };
        let mut device_write = env.open_device(&partition.path, true, true)?;
        let filesize = device_write.get_size()?;
        if filesize == 0 {
            return Err(anyhow!("Cannot get filesize of {}", partition.path));
        }
        device_write.seek(std::io::SeekFrom::Start(footer.vbmeta_offset.to_be()))?;
        device_write.write_all(&new_vbmeta.vbmeta_bytes)?;

        device_write.seek(std::io::SeekFrom::Start((filesize - FOOTER_SIZE) as u64))?;
        device_write.write_all(unsafe { std::slice::from_raw_parts(&footer as *const AvbFooter as *const u8, FOOTER_SIZE) })?;
    }
    warn!("Successfully patched all partitions");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io_delegate::MockEnvironment;
    use std::process::Command;

    struct Tempdir {
        dir: std::path::PathBuf,
    }

    static TEMP_ID: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

    impl Tempdir {
        fn new() -> Self {
            let id = TEMP_ID.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let dir = std::env::temp_dir();
            let dir = dir.join(format!("testkey-signer-tmp-{}", id));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("Failed to create tempdir");
            Self { dir }
        }
    }

    impl Drop for Tempdir {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.dir).expect("Failed to remove tempdir");
        }
    }

    fn prepare_boot_image(tempdir: &Tempdir) -> std::path::PathBuf {
        let outfile = tempdir.dir.join("bootmod.img");
        let mut f = std::fs::File::create_new(&outfile).expect("Failed to create bootmod.img");
        let mut data = b"boot testdata".to_vec();
        data.extend(vec![0; 4096 * 10 - data.len()]);
        f.write_all(&data).expect("Failed to write bootmod.img");
        drop(f);

        let output = Command::new("python3")
            .arg("tests/avbtool.py")
            .arg("add_hash_footer")
            .arg("--image")
            .arg(&outfile)
            .arg("--partition_size")
            .arg((4096 * 30).to_string())
            .arg("--partition_name")
            .arg("boot")
            .arg("--algorithm")
            .arg("SHA256_RSA4096")
            .arg("--key")
            .arg("testkey_rsa4096.pem")
            .arg("--rollback_index")
            .arg("123")
            .arg("--prop")
            .arg("abc:def")
            .output()
            .expect("Failed to run avbtool");

        assert!(
            output.status.success(),
            "avbtool failed\n--- stdout ---\n{}\n--- stderr ---\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );

        outfile
    }

    fn prepare_init_boot_image(tempdir: &Tempdir) -> std::path::PathBuf {
        let outfile = tempdir.dir.join("init_boot_mod.img");
        let mut f = std::fs::File::create_new(&outfile).expect("Failed to create init_boot_mod.img");
        let mut data = b"init_boot testdata".to_vec();
        data.extend(vec![0; 4096 * 10 - data.len()]);
        f.write_all(&data).expect("Failed to write init_boot_mod.img");
        drop(f);

        let output = Command::new("python3")
            .arg("tests/avbtool.py")
            .arg("add_hash_footer")
            .arg("--image")
            .arg(&outfile)
            .arg("--partition_size")
            .arg((4096 * 30).to_string())
            .arg("--partition_name")
            .arg("init_boot")
            .arg("--algorithm")
            .arg("NONE")
            .arg("--rollback_index")
            .arg("123")
            .arg("--prop")
            .arg("abc:def")
            .output()
            .expect("Failed to run avbtool");

        assert!(
            output.status.success(),
            "avbtool failed\n--- stdout ---\n{}\n--- stderr ---\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );

        outfile
    }

    fn prepare_partition_set(tempdir: &Tempdir) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
        let boot_image = prepare_boot_image(tempdir);
        let init_boot_image = prepare_init_boot_image(tempdir);
        let outfile = tempdir.dir.join("vbmetaout.img");

        let output = Command::new("python3")
            .arg("tests/avbtool.py")
            .arg("make_vbmeta_image")
            .arg("--output")
            .arg(&outfile)
            .arg("--padding_size")
            .arg("4096")
            .arg("--algorithm")
            .arg("SHA256_RSA4096")
            .arg("--key")
            .arg("testkey_rsa4096.pem")
            .arg("--rollback_index")
            .arg("456")
            .arg("--prop")
            .arg("ghi:jkl")
            .arg("--include_descriptors_from_image")
            .arg(init_boot_image.to_str().unwrap())
            .arg("--chain_partition")
            .arg("boot:1:testkey_rsa4096.avbpubkey")
            .output()
            .expect("Failed to run avbtool");

        assert!(
            output.status.success(),
            "avbtool failed\n--- stdout ---\n{}\n--- stderr ---\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );

        (outfile, boot_image, init_boot_image)
    }

    fn verify_file(tempdir: &Tempdir, filename: &str, expected_status: bool) {
        let outfile = tempdir.dir.join(filename);
        let output = Command::new("python3")
            .arg("tests/avbtool.py")
            .arg("verify_image")
            .arg("--image")
            .arg(&outfile)
            .arg("--key")
            .arg("testkey_rsa4096.pem")
            .output()
            .expect("Failed to run avbtool");

        assert!(
            output.status.success() == expected_status,
            "avbtool verify failed for active slot\n--- stdout ---\n{}\\n--- stderr ---\\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn verify_file_without_key(tempdir: &Tempdir, filename: &str, expected_status: bool) {
        let outfile = tempdir.dir.join(filename);
        let output = Command::new("python3")
            .arg("tests/avbtool.py")
            .arg("verify_image")
            .arg("--image")
            .arg(&outfile)
            .output()
            .expect("Failed to run avbtool");

        assert!(
            output.status.success() == expected_status,
            "avbtool verify failed for active slot\n--- stdout ---\n{}\\n--- stderr ---\\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn verify_image_data(tempdir: &Tempdir, patched_data: &[u8], expected_status: bool) {
        let outfile = tempdir.dir.join("tmp_data.img");
        std::fs::write(&outfile, &patched_data).expect("Failed to write mock patched data A");

        verify_file(tempdir, "tmp_data.img", expected_status);

        std::fs::remove_file(&outfile).expect("Failed to remove tmp_data.img");
    }

    fn verify_partition_set(tempdir: &Tempdir, vbmeta_data: &[u8], bootimg: &[u8], init_bootimg: &[u8], expected_status: bool) {
        let vbmeta_file = tempdir.dir.join("vbmeta.img");
        std::fs::write(&vbmeta_file, &vbmeta_data).expect("Failed to write mock vbmeta.img");
        let bootimg_file = tempdir.dir.join("boot.img");
        std::fs::write(&bootimg_file, &bootimg).expect("Failed to write mock boot.img");
        let init_bootimg_file = tempdir.dir.join("init_boot.img");
        std::fs::write(&init_bootimg_file, &init_bootimg).expect("Failed to write mock init_boot.img");

        let output = Command::new("python3")
            .arg("tests/avbtool.py")
            .arg("verify_image")
            .arg("--image")
            .arg(&vbmeta_file)
            .arg("--key")
            .arg("testkey_rsa4096.pem")
            .arg("--expected_chain_partition")
            .arg("boot:1:testkey_rsa4096.avbpubkey")
            .arg("--use_partition_name")
            .output()
            .expect("Failed to run avbtool");

        assert!(
            output.status.success() == expected_status,
            "avbtool verify failed for active slot\n--- stdout ---\n{}\\n--- stderr ---\\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );

        std::fs::remove_file(&vbmeta_file).expect("Failed to remove vbmeta.img");
        std::fs::remove_file(&bootimg_file).expect("Failed to remove boot.img");
        std::fs::remove_file(&init_bootimg_file).expect("Failed to remove init_boot.img");
    }

    #[test]
    fn test_patch_file() {
        let tempdir = Tempdir::new();

        let bootimg = prepare_boot_image(&tempdir);

        let mut f = std::fs::OpenOptions::new().read(true).write(true).open(&bootimg).expect("Failed to open bootmod.img");
        f.seek(std::io::SeekFrom::Start(2)).expect("Failed to seek");
        f.write_all(b"ch").expect("Failed to write bootmod.img");
        drop(f);

        verify_file(&tempdir, bootimg.to_str().unwrap(), false);

        run(
            Args {
                command: Commands::PatchSingleFile {
                    input_filename: bootimg.to_str().unwrap().to_string(),
                    output_filename: Some(tempdir.dir.join("bootmodout.img").to_str().unwrap().to_string()),
                },
                log_level: Some("info".to_string()),
            },
            &RealEnvironment,
        )
        .expect("Failed to run test_patch_file");

        verify_file(&tempdir, "bootmodout.img", true);
    }

    #[test]
    fn test_patch_init_boot_file() {
        let tempdir = Tempdir::new();

        let bootimg = prepare_init_boot_image(&tempdir);

        let mut f = std::fs::OpenOptions::new().read(true).write(true).open(&bootimg).expect("Failed to open init_boot_mod.img");
        f.seek(std::io::SeekFrom::Start(2)).expect("Failed to seek");
        f.write_all(b"ch").expect("Failed to write init_boot_mod.img");
        drop(f);

        verify_file(&tempdir, bootimg.to_str().unwrap(), false);

        run(
            Args {
                command: Commands::PatchSingleFile {
                    input_filename: bootimg.to_str().unwrap().to_string(),
                    output_filename: Some(tempdir.dir.join("init_boot_mod_out.img").to_str().unwrap().to_string()),
                },
                log_level: Some("info".to_string()),
            },
            &RealEnvironment,
        )
        .expect("Failed to run test_patch_init_boot_file");

        verify_file_without_key(&tempdir, "init_boot_mod_out.img", true);
    }

    // #[test]
    // fn test_mock_device() {
    //     use crate::io_delegate::MockDevice;

    //     let tempdir = Tempdir::new();
    //     let bootimg = prepare_boot_image(&tempdir);
    //     let mut data = std::fs::read(&bootimg).expect("Failed to read bootimg");

    //     data[2] = b'c';
    //     data[3] = b'h';

    //     let mut mock_device = MockDevice::new(data);

    //     // Run patch action using the mock device instead of actual file
    //     run_patch_device(&mock_env, &Commands::PatchDevice { yes: true, inactive_slot: false }, "mock_boot", &mut mock_device).expect("Failed to run patch on mock device");

    //     // Verify that the mock device was written securely
    //     let patched_data = mock_device.into_inner();

    //     verify_image_data(&tempdir, &patched_data, true);
    // }

    #[test]
    fn test_patch_device_slots() {
        use std::collections::HashMap;
        use crate::io_delegate::MockDevice;

        let _ = env_logger::builder().is_test(true).try_init();

        let tempdir = Tempdir::new();
        let (vbmetaimg, bootimg, init_bootimg) = prepare_partition_set(&tempdir);
        let vbmeta_data = std::fs::read(&vbmetaimg).expect("Failed to read vbmeta.img");
        let boot_data = std::fs::read(&bootimg).expect("Failed to read boot.img");
        let init_boot_data = std::fs::read(&init_bootimg).expect("Failed to read init_boot.img");

        let mut vbmeta_data_a = vbmeta_data.clone();
        let mut vbmeta_data_b = vbmeta_data.clone();
        let mut boot_data_a = boot_data.clone();
        let mut boot_data_b = boot_data.clone();
        let mut init_boot_data_a = init_boot_data.clone();
        let mut init_boot_data_b = init_boot_data.clone();

        // Slightly modify them to differ
        boot_data_a[2] = b'a';
        boot_data_b[2] = b'b';

        let init_boot_mod_data = b"It is modified init_boot.img content";
        init_boot_data_a[0..init_boot_mod_data.len()].copy_from_slice(init_boot_mod_data);
        init_boot_data_b[0..init_boot_mod_data.len()].copy_from_slice(init_boot_mod_data);


        let mut props = HashMap::new();
        props.insert("ro.boot.slot_suffix".to_string(), "_a".to_string());

        let mut devices = HashMap::new();
        devices.insert("/dev/block/by-name/vbmeta_a".to_string(), MockDevice::new(vbmeta_data_a.clone()));
        devices.insert("/dev/block/by-name/vbmeta_b".to_string(), MockDevice::new(vbmeta_data_b.clone()));
        devices.insert("/dev/block/by-name/boot_a".to_string(), MockDevice::new(boot_data_a.clone()));
        devices.insert("/dev/block/by-name/boot_b".to_string(), MockDevice::new(boot_data_b.clone()));
        devices.insert("/dev/block/by-name/init_boot_a".to_string(), MockDevice::new(init_boot_data_a.clone()));
        devices.insert("/dev/block/by-name/init_boot_b".to_string(), MockDevice::new(init_boot_data_b.clone()));

        let mock_env = MockEnvironment {
            props,
            devices: std::sync::Mutex::new(devices),
        };

        // Patch active slot (_a)
        run(
            Args {
                command: Commands::PatchDevice { yes: true, inactive_slot: false },
                log_level: Some("info".to_string()),
            },
            &mock_env,
        )
        .expect("Failed to patch active slot");

        // Verify active slot was patched securely (check 'a' at offset 2, patched VBMeta correctly via verify_image)
        let binding = mock_env.devices.lock().unwrap();
        let patched_vbmeta_data_a = binding.get("/dev/block/by-name/vbmeta_a").expect("vbmeta_a not found").into_inner();
        let patched_boot_data_a = binding.get("/dev/block/by-name/boot_a").expect("boot_a not found").into_inner();
        let patched_init_boot_data_a = binding.get("/dev/block/by-name/init_boot_a").expect("init_boot_a not found").into_inner();
        let unpatched_vbmeta_data_b = binding.get("/dev/block/by-name/vbmeta_b").expect("vbmeta_b not found").into_inner();
        let unpatched_boot_data_b = binding.get("/dev/block/by-name/boot_b").expect("boot_b not found").into_inner();
        let unpatched_init_boot_data_b = binding.get("/dev/block/by-name/init_boot_b").expect("init_boot_b not found").into_inner();
        drop(binding);

        verify_partition_set(&tempdir, &patched_vbmeta_data_a, &patched_boot_data_a, &patched_init_boot_data_a, true);
        verify_partition_set(&tempdir, &unpatched_vbmeta_data_b, &unpatched_boot_data_b, &unpatched_init_boot_data_b, false);
        // Patch inactive slot (_b)
        run(
            Args {
                command: Commands::PatchDevice { yes: true, inactive_slot: true },
                log_level: Some("info".to_string()),
            },
            &mock_env,
        )
        .expect("Failed to patch inactive slot");

        // Verify inactive slot was patched securely
        let binding = mock_env.devices.lock().unwrap();
        let patched_vbmeta_data_a = binding.get("/dev/block/by-name/vbmeta_a").expect("vbmeta_a not found").into_inner();
        let patched_boot_data_a = binding.get("/dev/block/by-name/boot_a").expect("boot_a not found").into_inner();
        let patched_init_boot_data_a = binding.get("/dev/block/by-name/init_boot_a").expect("init_boot_a not found").into_inner();
        let patched_vbmeta_data_b = binding.get("/dev/block/by-name/vbmeta_b").expect("vbmeta_b not found").into_inner();
        let patched_boot_data_b = binding.get("/dev/block/by-name/boot_b").expect("boot_b not found").into_inner();
        let patched_init_boot_data_b = binding.get("/dev/block/by-name/init_boot_b").expect("init_boot_b not found").into_inner();
        drop(binding);

        verify_partition_set(&tempdir, &patched_vbmeta_data_a, &patched_boot_data_a, &patched_init_boot_data_a, true);
        verify_partition_set(&tempdir, &patched_vbmeta_data_b, &patched_boot_data_b, &patched_init_boot_data_b, true);
    }
}
