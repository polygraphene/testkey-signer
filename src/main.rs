mod avb;
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

use crate::avb::AvbAlgorithmType;
use crate::avb::AvbDescriptorEnum;
use crate::avb::AvbFooter;
use crate::avb::AvbHashDescriptorInfo;
use crate::avb::AvbRSAPublicKey;
use crate::avb::AvbRSAPublicKeyHeader;
use crate::avb::AvbVBMetaImageHeader;
use crate::avb::AVB_FOOTER_MAGIC;
use crate::avb::FOOTER_SIZE;
use crate::avb::PUBLIC_EXPONENT;
use crate::avb::VBMETA_ALIGN;
use crate::avb::VBMeta;

use crate::hasher::Hasher;
use crate::testkey::TESTKEY_2048;
use crate::testkey::TESTKEY_4096;

struct Partition {
    name: String,
    path: String,
    is_device: bool,
}

const SUPPORTED_PARTITIONS: [&str; 5] = ["boot", "init_boot", "vendor_boot", "dtbo", "recovery"];

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

fn padding_size(len: usize, align: usize) -> usize {
    (len + align - 1) / align * align - len
}

fn pad_right(val: &mut Vec<u8>, align: usize) {
    val.extend(vec![0; padding_size(val.len(), align)]);
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

#[derive(Debug, Clone, Copy)]
enum KeyBits {
    Key2048,
    Key4096,
}

struct PartitionInfo {
    original_image_size: usize,
    partition_sizes_match: bool,
    partition_hashes_match: bool,
}

struct ParsedHeaders {
    key_num_bits: Option<KeyBits>,
    header: VBMeta,
    partition_info: Option<PartitionInfo>,
    vbmeta_hashes_match: Option<bool>,
    vbmeta_signatures_match: Option<bool>,
    new_descriptors: Vec<AvbDescriptorEnum>,
    parent_vbmeta_hash_descriptor: Option<AvbHashDescriptorInfo>,
    incorrect_hash_descriptor_num: Option<usize>,
}

impl ParsedHeaders {
    fn is_valid(&self) -> bool {
        self.vbmeta_hashes_match.unwrap_or(true) && self.vbmeta_signatures_match.unwrap_or(true) && self.partition_info.as_ref().map_or(true, |p| p.partition_sizes_match && p.partition_hashes_match)
    }

    fn print_result(&self) {
        let f = |b| if let Some(b) = b { if b { "OK" } else { "NG" } } else { "N/A" };
        let g = |b| if b { "OK" } else { "NG" };
        info!("VBMeta Hash: {}", f(self.vbmeta_hashes_match));
        info!("VBMeta Signature: {}", f(self.vbmeta_signatures_match));
        info!("Partition Hash: {}", self.partition_info.as_ref().map_or("N/A", |p| g(p.partition_hashes_match)));
        info!("Partition Size: {}", self.partition_info.as_ref().map_or("N/A", |p| g(p.partition_sizes_match)));
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

fn parse_vbmeta(f: &mut dyn IoDelegate, is_vbmeta: bool, replace_hash_descriptors: Option<&HashMap<String, AvbHashDescriptorInfo>>) -> Result<ParsedHeaders> {
    let vbmeta = VBMeta::from_device(f)?;

    if vbmeta.footer.is_some() && is_vbmeta {
        return Err(anyhow!("VBMeta footer found in vbmeta image."));
    }
    if !vbmeta.footer.is_some() && !is_vbmeta {
        return Err(anyhow!("Footer not found in partition image."));
    }

    let algo_type = vbmeta.header.algorithm_type;
    let (vbmeta_hashes_match, vbmeta_signatures_match, key_bits) = if algo_type == AvbAlgorithmType::AVB_ALGORITHM_TYPE_NONE as u32 {
        // Non chained partition. No verification for hashes or signatures.
        (None, None, None)
    } else {
        let mut hasher = Hasher::new(algo_type)?;
        hasher.update(&vbmeta.header.to_be_bytes());
        hasher.update(&vbmeta.auxiliary_data);
        let hash_calc = hasher.finalize();

        let hash_in_vbmeta = vbmeta.header.get_hash(&vbmeta.authentication_data)?;

        let vbmeta_hashes_match = hash_calc == hash_in_vbmeta;
        if hash_calc == hash_in_vbmeta {
            info!("Hashes of VBMeta matched");
        }

        let public_key_data = vbmeta.header.get_public_key(&vbmeta.auxiliary_data)?;
        let public_key = AvbRSAPublicKey::from_bytes(public_key_data)?;
        let num_bits = public_key.header.key_num_bits;

        let n = BigUint::from_bytes_be(&public_key.modulus);
        let e = BigUint::from(PUBLIC_EXPONENT);
        let pubkey = RsaPublicKey::new(n, e)?;

        let verifying_key = VerifyingKey::<rsa::sha2::Sha256>::new(pubkey);

        let sig_value = vbmeta.header.get_signature(&vbmeta.authentication_data)?;
        let signature = rsa::pkcs1v15::Signature::try_from(sig_value)?;
        let vbmeta_signatures_match = match verifying_key.verify_prehash(hash_in_vbmeta, &signature) {
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

    let original_image = if let Some(footer) = vbmeta.footer {
        f.seek(std::io::SeekFrom::Start(0))?;
        let mut image_data = vec![0; footer.original_image_size as usize];
        f.read_exact(&mut image_data)?;
        Some((footer.original_image_size, image_data))
    } else {
        None
    };

    let mut partition_hashes_match = false;
    let mut parititon_sizes_match = false;
    let mut new_descriptors = vec![];
    let mut parent_vbmeta_hash_descriptor = None;
    let mut incorrect_hash_descriptor_num = 0;
    for descriptor in &vbmeta.descriptors {
        match descriptor {
            AvbDescriptorEnum::Hash(hash_descriptor) => {
                debug!("Hash descriptor information:");
                debug!("Algorithm: {}", hash_descriptor.descriptor.algorithm_name());
                debug!("Partition name: {}", String::from_utf8_lossy(&hash_descriptor.partition_name));
                debug!("Salt  : {}", hex(&hash_descriptor.salt));
                debug!("Digest: {}", hex(&hash_descriptor.digest));
                let algo_name = hash_descriptor.descriptor.algorithm_name();

                match original_image {
                    // For non-vbmeta partitions, calculate hash and fix size.
                    Some((original_image_size, ref image_data)) => {
                        let mut hasher = Hasher::new_by_name(&algo_name)?;
                        hasher.update(&hash_descriptor.salt);
                        hasher.update(&image_data);
                        let hash_partition_calc = hasher.finalize();
                        info!("New partition hash: {}", hex(&hash_partition_calc));
                        if hash_partition_calc == hash_descriptor.digest {
                            info!("Partition hashes match");
                            partition_hashes_match = true;
                        } else {
                            info!("Hashes did not match");
                        }
                        let mut new_descriptor = hash_descriptor.clone();
                        // Fix it up because many(?) boot modification tools don't fix this. They only patch original_image_size on AvbFooter.
                        if new_descriptor.descriptor.image_size != original_image_size {
                            info!("Partition sizes mismatch in hash descriptor. Fix it.");
                            new_descriptor.descriptor.image_size = original_image_size;
                        } else {
                            info!("Partition sizes match");
                            parititon_sizes_match = true;
                        }

                        new_descriptor.digest = hash_partition_calc;
                        new_descriptor.fix_header();
                        new_descriptors.push(AvbDescriptorEnum::Hash(new_descriptor.clone()));

                        parent_vbmeta_hash_descriptor = Some(new_descriptor);
                    }
                    // For vbmeta partitions, use the provided child hash descriptors.
                    _ => {
                        if let (Some(replace_hash_descriptors), Some(partition_name)) = (replace_hash_descriptors, &vbmeta.partition_name) {
                            if let Some(new_hash_desc) = replace_hash_descriptors.get(partition_name) {
                                info!("Replacing hash descriptors for {partition_name} in vbmeta partition buffer.");
                                trace!("{}", hexdump(&new_hash_desc.to_be_bytes()));
                                if new_hash_desc.digest != hash_descriptor.digest {
                                    incorrect_hash_descriptor_num += 1;
                                }
                                new_descriptors.push(AvbDescriptorEnum::Hash(new_hash_desc.clone()));
                            } else {
                                new_descriptors.push(AvbDescriptorEnum::Hash(hash_descriptor.clone()));
                            }
                        } else {
                            new_descriptors.push(AvbDescriptorEnum::Hash(hash_descriptor.clone()));
                        }
                    }
                };
            }
            _ => {
                new_descriptors.push(descriptor.clone());
            }
        }
    }

    let partition_info = if let Some((original_image_size, _image_data)) = original_image {
        Some(PartitionInfo {
            original_image_size: original_image_size as usize,
            partition_hashes_match: partition_hashes_match,
            partition_sizes_match: parititon_sizes_match,
        })
    } else {
        None
    };

    Ok(ParsedHeaders {
        key_num_bits: key_bits,
        header: vbmeta,
        partition_info: partition_info,
        vbmeta_hashes_match,
        vbmeta_signatures_match,
        new_descriptors,
        parent_vbmeta_hash_descriptor,
        incorrect_hash_descriptor_num: if replace_hash_descriptors.is_some() { Some(incorrect_hash_descriptor_num) } else { None },
    })
}

struct GeneratedHeaders {
    vbmeta_bytes: Vec<u8>,
    footer: Option<AvbFooter>,
}

fn generate_new_header(header: &AvbVBMetaImageHeader, new_descriptors: Vec<AvbDescriptorEnum>, key: Option<RsaPrivateKey>, original_image_size: Option<usize>) -> Result<GeneratedHeaders> {
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
    let pubkey_bytes = if let Some(key) = &key { convert_to_avb_pubkey(&key.to_public_key())? } else { vec![] };

    new_header.authentication_data_block_size = new_header.signature_offset + new_header.signature_size;
    let authentication_pad = vec![0; padding_size(new_header.authentication_data_block_size as usize, VBMETA_ALIGN)];
    new_header.authentication_data_block_size += authentication_pad.len() as u64;

    let mut new_descriptors_data = vec![];
    for descriptor in new_descriptors {
        new_descriptors_data.extend(descriptor.to_be_bytes());
    }
    new_header.descriptors_offset = 0;
    new_header.descriptors_size = new_descriptors_data.len() as u64;
    new_header.public_key_offset = new_header.descriptors_offset + new_header.descriptors_size;
    new_header.public_key_size = pubkey_bytes.len() as u64;
    new_header.public_key_metadata_offset = new_header.public_key_offset + new_header.public_key_size;
    new_header.public_key_metadata_size = 0;

    new_header.auxiliary_data_block_size = new_header.public_key_metadata_offset + new_header.public_key_metadata_size;
    let auxiliary_pad = vec![0; padding_size(new_header.auxiliary_data_block_size as usize, VBMETA_ALIGN)];
    new_header.auxiliary_data_block_size += auxiliary_pad.len() as u64;

    let new_header_bytes = new_header.to_be_bytes();

    let (new_hash, new_signature) = if let Some(key) = &key {
        // Signature target is VBMeta header + Auxiliary data block.
        let mut hasher = Hasher::new(algo_type)?;
        hasher.update(&new_header_bytes);
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
    vbmeta_bytes.extend_from_slice(&new_header_bytes);
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
        Some(footer)
    } else {
        None
    };

    Ok(GeneratedHeaders {
        vbmeta_bytes: vbmeta_bytes,
        footer: footer,
    })
}

fn patch_boot_spl(descriptors_data: &mut Vec<AvbDescriptorEnum>, boot_spl: &str) {
    for descriptor in descriptors_data.iter_mut() {
        if let AvbDescriptorEnum::Property(property_descriptor) = descriptor {
            if property_descriptor.key == b"com.android.build.boot.security_patch" {
                info!("Patching boot security patch from {} to {}", String::from_utf8_lossy(&property_descriptor.value), boot_spl);
                property_descriptor.value = boot_spl.as_bytes().to_vec();
                property_descriptor.fix_header();
            }
        }
    }
}

/// Read VBMeta from device or files and patch it.
#[derive(Parser, Debug)]
#[command(version, about, long_about = None, after_help = "Example:
 # Patch current slot partitions
 testkey-signer patch-device [--inactive-slot] [--dry-run] [--boot-spl 2025-03-05]
 # Verify current slot partitions
 testkey-signer verify-device [--inactive-slot]
 # Patch files. Files will be patched in place.
 testkey-signer patch-file boot.img [--boot-spl 2025-03-05]
 # Can patch multiple files at once. Non-chained partition must be patched simultaneously.
 testkey-signer patch-file vbmeta.img boot.img init_boot.img ... [--boot-spl 2025-03-05]
 # Just verify files
 testkey-signer verify-file boot.img")]
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
        #[arg(short = 'y', long = "yes")]
        yes: bool,

        /// Patch inactive slot instead of current slot.
        #[arg(short = 'i', long = "inactive-slot")]
        inactive_slot: bool,

        /// Don't write to devices, just show what will be done.
        #[arg(short = 'n', long = "dry-run")]
        dry_run: bool,

        /// Patch SPL for boot partition. Format: YYYY-MM-DD
        #[arg(short = 'b', long = "boot-spl")]
        boot_spl: Option<String>,
    },
    /// Verify current slot partitions.
    VerifyDevice {
        /// Verify inactive slot instead of current slot.
        #[arg(short = 'i', long = "inactive-slot")]
        inactive_slot: bool,
    },
    /// Patch files. Files will be patched in place.
    #[command(arg_required_else_help = true)]
    PatchFile {
        /// Input filenames.
        input_filenames: Vec<String>,

        /// Patch SPL for boot partition. Format: YYYY-MM-DD.
        #[arg(short = 'b', long = "boot-spl")]
        boot_spl: Option<String>,
    },
    /// Verify files.
    #[command(arg_required_else_help = true)]
    VerifyFile {
        /// Input filenames.
        input_filenames: Vec<String>,
    },
}

fn main() -> Result<()> {
    // Default log level is info. Set RUST_LOG=debug for more logs.
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    run(Args::parse(), &RealEnvironment)
}

fn run(args: Args, env: &dyn Environment) -> Result<()> {
    match args.command {
        Commands::PatchDevice {
            inactive_slot,
            yes,
            dry_run,
            boot_spl,
        } => {
            return run_patch_device(env, inactive_slot, yes, dry_run, boot_spl);
        }
        Commands::VerifyDevice { inactive_slot } => {
            return run_patch_device(env, inactive_slot, false, true, None);
        }
        Commands::PatchFile { input_filenames, boot_spl } => {
            return run_patch_files(env, input_filenames, false, boot_spl);
        }
        Commands::VerifyFile { input_filenames } => {
            return run_patch_files(env, input_filenames, true, None);
        }
    }
}

fn run_patch_files(env: &dyn Environment, input_filenames: Vec<String>, dry_run: bool, boot_spl: Option<String>) -> Result<()> {
    let mut partition_set = HashMap::new();
    let mut vbmeta_idx = None;
    for (i, input_filename) in input_filenames.iter().enumerate() {
        let mut device = env.open_device(input_filename, false, false)?;

        if !AvbFooter::file_has_footer(device.as_mut())? {
            // It must be vbmeta.
            if vbmeta_idx.is_some() {
                return Err(anyhow!("Multiple vbmeta files found: {} and {}", input_filenames[vbmeta_idx.unwrap()], input_filename));
            }
            vbmeta_idx = Some(i);
            partition_set.insert(
                "vbmeta".to_string(),
                Partition {
                    name: "vbmeta".to_string(),
                    path: input_filename.to_string(),
                    is_device: false,
                },
            );
        } else {
            let partition_name = VBMeta::get_partition_name(device.as_mut())?;
            partition_set.insert(
                partition_name.to_string(),
                Partition {
                    name: partition_name.to_string(),
                    path: input_filename.to_string(),
                    is_device: false,
                },
            );
        }
    }

    run_patch(env, partition_set, true, dry_run, boot_spl)
}

fn get_test_key(key_num_bits: Option<KeyBits>) -> Result<Option<RsaPrivateKey>> {
    match key_num_bits {
        Some(key_bits) => {
            let testkey = match key_bits {
                KeyBits::Key2048 => TESTKEY_2048,
                KeyBits::Key4096 => TESTKEY_4096,
            };
            Ok(Some(RsaPrivateKey::from_pkcs1_pem(String::from_utf8(testkey.to_vec())?.as_str())?))
        }
        None => Ok(None),
    }
}

fn run_patch_device(env: &dyn Environment, inactive_slot: bool, yes: bool, dry_run: bool, boot_spl: Option<String>) -> Result<()> {
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
        if env.device_exists(&path) {
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
    let vbmeta_device = format!("/dev/block/by-name/vbmeta{slot_suffix}");
    if !env.device_exists(&vbmeta_device) {
        return Err(anyhow!("VBMeta device not found."));
    }
    partition_set.insert(
        "vbmeta".to_string(),
        Partition {
            name: "vbmeta".to_string(),
            path: vbmeta_device,
            is_device: true,
        },
    );

    run_patch(env, partition_set, yes, dry_run, boot_spl)
}

fn run_patch(env: &dyn Environment, partition_set: HashMap<String, Partition>, yes: bool, dry_run: bool, boot_spl: Option<String>) -> Result<()> {
    let mut parsed_vbmeta_list = vec![];
    let mut replace_hash_descriptors = HashMap::new();
    let mut has_non_chained_partition = false;
    for partition in partition_set.values() {
        if partition.name == "vbmeta" {
            continue;
        }
        let mut device = env.open_device(&partition.path, partition.is_device, false)?;
        info!("Parsing VBMeta for {}", partition.path);
        let mut parsed = parse_vbmeta(device.as_mut(), false, None).context(format!("Failed to parse VBMeta for {}", partition.path))?;
        if let Some(parent_vbmeta_hash_descriptor) = &mut parsed.parent_vbmeta_hash_descriptor {
            replace_hash_descriptors.insert(partition.name.clone(), parent_vbmeta_hash_descriptor.clone());
            has_non_chained_partition = true;
        }
        if let Some(boot_spl) = &boot_spl {
            patch_boot_spl(&mut parsed.new_descriptors, boot_spl);
        }
        parsed_vbmeta_list.push((partition, parsed));
    }

    match partition_set.get("vbmeta") {
        Some(vbmeta) => {
            let vbmeta_device = vbmeta.path.clone();
            let mut device = env.open_device(&vbmeta_device, vbmeta.is_device, false)?;

            info!("Parsing VBMeta for {vbmeta_device}.");
            let mut parsed = parse_vbmeta(device.as_mut(), true, Some(&replace_hash_descriptors)).context(format!("Failed to parse VBMeta for {vbmeta_device}"))?;
            if let Some(boot_spl) = &boot_spl {
                patch_boot_spl(&mut parsed.new_descriptors, boot_spl);
            }

            for (partition, parsed) in &parsed_vbmeta_list {
                info!("Partition {}", partition.name);
                parsed.print_result();
            }
            info!("Partition vbmeta");
            parsed.print_result();
            let parent_descriptors_ok = parsed.incorrect_hash_descriptor_num.expect("Should have incorrect_hash_descriptor_num") == 0;
            info!("Parent descriptors ok: {}", parent_descriptors_ok);
            if parsed.is_valid() && parsed_vbmeta_list.iter().all(|(_, parsed)| parsed.is_valid()) && boot_spl.is_none() && parent_descriptors_ok {
                info!("Hash and signature are all okay. So no need to re-sign. Exit.");
                return Ok(());
            }
            if dry_run {
                info!("Dry run, not writing to devices.");
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

            let new_vbmeta = generate_new_header(&parsed.header.header, parsed.new_descriptors, testkey, parsed.partition_info.as_ref().map(|p| p.original_image_size))?;

            env.set_writable(&vbmeta_device, vbmeta.is_device)?;
            let mut device_write = env.open_device(&vbmeta_device, true, true)?;

            device_write.write_all(&new_vbmeta.vbmeta_bytes)?;

            warn!("Successfully patched {vbmeta_device}");
        }
        None => {
            if has_non_chained_partition {
                warn!("No vbmeta file found, but non-chained partitions are present. Skipping VBMeta patching.");
            }
            for (partition, parsed) in &parsed_vbmeta_list {
                info!("Partition {}", partition.name);
                parsed.print_result();
            }
            if parsed_vbmeta_list.iter().all(|(_, parsed)| parsed.is_valid()) && boot_spl.is_none() {
                info!("Hash and signature are all okay. So no need to re-sign. Exit.");
                return Ok(());
            }
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
        }
    }

    for (partition, parsed) in parsed_vbmeta_list.into_iter() {
        info!("Patching {}", partition.path);
        let testkey = get_test_key(parsed.key_num_bits)?;
        let new_vbmeta = generate_new_header(&parsed.header.header, parsed.new_descriptors, testkey, parsed.partition_info.as_ref().map(|p| p.original_image_size))?;
        let Some(footer) = new_vbmeta.footer else {
            return Err(anyhow!("No footer was generated"));
        };
        env.set_writable(&partition.path, partition.is_device)?;
        let mut device_write = env.open_device(&partition.path, partition.is_device, true)?;
        let filesize = device_write.get_size()?;
        if filesize == 0 {
            return Err(anyhow!("Cannot get filesize of {}", partition.path));
        }
        device_write.seek(std::io::SeekFrom::Start(footer.vbmeta_offset))?;
        device_write.write_all(&new_vbmeta.vbmeta_bytes)?;

        device_write.seek(std::io::SeekFrom::Start((filesize - FOOTER_SIZE) as u64))?;
        device_write.write_all(&footer.to_be_bytes())?;
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
    static SALT: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

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
            .arg("--salt")
            .arg(SALT)
            .arg("--key")
            .arg("testkey_rsa4096.pem")
            .arg("--rollback_index")
            .arg("123")
            .arg("--prop")
            .arg("abc:def")
            .arg("--prop")
            .arg("com.android.build.boot.security_patch:2026-01-01")
            .arg("--prop")
            .arg("com.android.build.boot.os_version:15")
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
            .arg("--salt")
            .arg(SALT)
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

    // fn verify_image_data(tempdir: &Tempdir, patched_data: &[u8], expected_status: bool) {
    //     let outfile = tempdir.dir.join("tmp_data.img");
    //     std::fs::write(&outfile, &patched_data).expect("Failed to write mock patched data A");

    //     verify_file(tempdir, "tmp_data.img", expected_status);

    //     std::fs::remove_file(&outfile).expect("Failed to remove tmp_data.img");
    // }

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

    fn get_boot_spl(tempdir: &Tempdir, data: &[u8]) -> Result<String> {
        let tmpfile = tempdir.dir.join("tmp.img");
        let mut f = std::fs::File::create(&tmpfile).expect("Failed to create tmp.img");
        f.write_all(data).expect("Failed to write tmp.img");
        drop(f);

        let output = Command::new("python3")
            .arg("tests/avbtool.py")
            .arg("info_image")
            .arg("--image")
            .arg(&tmpfile)
            .output()
            .expect("Failed to run avbtool");

        assert!(
            output.status.success(),
            "avbtool info_image failed\n--- stdout ---\n{}\\n--- stderr ---\\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );

        let output = String::from_utf8_lossy(&output.stdout);
        for line in output.lines() {
            let line = line.trim();
            const PREFIX: &str = "Prop: com.android.build.boot.security_patch -> '";
            if line.starts_with(PREFIX) {
                return Ok(line[PREFIX.len()..line.len() - 1].to_string());
            }
        }
        Err(anyhow!("Prop not found"))
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
                command: Commands::PatchFile {
                    input_filenames: vec![bootimg.to_str().unwrap().to_string()],
                    boot_spl: None,
                },
                log_level: Some("info".to_string()),
            },
            &RealEnvironment,
        )
        .expect("Failed to run test_patch_file");

        verify_file(&tempdir, bootimg.to_str().unwrap(), true);
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
                command: Commands::PatchFile {
                    input_filenames: vec![bootimg.to_str().unwrap().to_string()],
                    boot_spl: None,
                },
                log_level: Some("info".to_string()),
            },
            &RealEnvironment,
        )
        .expect("Failed to run test_patch_init_boot_file");

        verify_file_without_key(&tempdir, bootimg.to_str().unwrap(), true);
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

        let vbmeta_data_a = vbmeta_data.clone();
        let vbmeta_data_b = vbmeta_data.clone();
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
                command: Commands::PatchDevice { yes: true, inactive_slot: false, dry_run: false, boot_spl: Some("Modified boot spl".to_string()) },
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
        assert_eq!(get_boot_spl(&tempdir, &patched_boot_data_a).expect("Failed to get boot spl"), "Modified boot spl");
        // Patch inactive slot (_b)
        run(
            Args {
                command: Commands::PatchDevice { yes: true, inactive_slot: true, dry_run: false, boot_spl: Some("Modified boot spl 2".to_string()) },
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
        assert_eq!(get_boot_spl(&tempdir, &patched_boot_data_b).expect("Failed to get boot spl"), "Modified boot spl 2");
    }

    #[test]
    fn test_verify_file() {
        let tempdir = Tempdir::new();
        let (vbmetaimg, bootimg, init_bootimg) = prepare_partition_set(&tempdir);
        let vbmeta_data = std::fs::read(&vbmetaimg).expect("Failed to read vbmeta.img");
        let boot_data = std::fs::read(&bootimg).expect("Failed to read boot.img");
        let init_boot_data = std::fs::read(&init_bootimg).expect("Failed to read init_boot.img");

        run(
            Args {
                command: Commands::VerifyFile { input_filenames: vec![vbmetaimg.to_str().unwrap().to_string(), bootimg.to_str().unwrap().to_string(), init_bootimg.to_str().unwrap().to_string()] },
                log_level: Some("info".to_string()),
            },
            &RealEnvironment {},
        )
        .expect("Failed to verify file");
    }
}
