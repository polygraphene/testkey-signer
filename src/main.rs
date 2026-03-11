mod bindings;
mod testkey;

use std::io::Read;
use std::io::Seek;
use std::io::Write;
use std::os::unix::fs::MetadataExt;

use bindings::AvbAlgorithmType;
use bindings::AvbDescriptorTag;
use bindings::AvbFooter;
use bindings::AvbRSAPublicKeyHeader;
use bindings::AvbVBMetaImageHeader;

use aws_lc_rs::digest;

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
use rsa::pkcs8::EncodePublicKey;
use rsa::sha2::Sha256;
use rsa::signature::SignatureEncoding;
use rsa::signature::Verifier;
use rsa::signature::hazmat::PrehashSigner;
use rsa::signature::hazmat::PrehashVerifier;
use rsa::traits::PublicKeyParts;

use crate::bindings::AvbDescriptor;
use crate::bindings::AvbHashDescriptor;

use testkey::TESTKEY_2048;
use testkey::TESTKEY_4096;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

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
        Err("Too long".into())
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

const FOOTER_SIZE: usize = std::mem::size_of::<AvbFooter>();
const HEADER_SIZE: usize = std::mem::size_of::<AvbVBMetaImageHeader>();
const PUBLIC_EXPONENT: u32 = 65537u32;
const MAX_VBMETA_SIZE: usize = 64 * 1024;
const MAX_FOOTER_SIZE: usize = 4096;

fn main() -> Result<()> {
    let args = std::env::args();
    let filename = args.skip(1).next().unwrap();
    let mut f = std::fs::File::open(&filename)?;
    let filesize = std::fs::metadata(&filename)?.size() as usize;

    let (header_offset, original_image_size) = if filesize >= FOOTER_SIZE {
        f.seek(std::io::SeekFrom::End(-(FOOTER_SIZE as i64)))?;
        let mut buf = vec![0; FOOTER_SIZE];
        f.read_exact(&mut buf)?;
        let footer = buf.as_ptr() as *const AvbFooter;
        let mut footer_dest = AvbFooter::default();
        avb_footer_to_host_byte_order(unsafe { &*footer }, &mut footer_dest);
        if &footer_dest.magic == b"AVBf" {
            let vbmeta_size = footer_dest.vbmeta_size;
            println!("vbmeta size: {}", vbmeta_size);
            (footer_dest.vbmeta_offset, footer_dest.original_image_size)
        } else {
            (0, 0)
        }
    } else {
        (0, 0)
    };
    println!(
        "header offset: {} original image size: {}",
        header_offset, original_image_size
    );

    f.seek(std::io::SeekFrom::Start(header_offset))?;
    let mut header_buf = vec![0; HEADER_SIZE];
    f.read_exact(&mut header_buf)?;

    let header_src = unsafe { &*(header_buf.as_ptr() as *const AvbVBMetaImageHeader) };
    let mut header = AvbVBMetaImageHeader::default();
    avb_vbmeta_image_header_to_host_byte_order(header_src, &mut header);

    match &header.magic {
        b"AVB0" => println!("Magic is AVB_MAGIC"),
        _ => return Err("VBMeta magic is not valid.".into()),
    }

    const SHA256_ALGOES: [u32; 3] = [
        AvbAlgorithmType::AVB_ALGORITHM_TYPE_SHA256_RSA2048 as u32,
        AvbAlgorithmType::AVB_ALGORITHM_TYPE_SHA256_RSA4096 as u32,
        AvbAlgorithmType::AVB_ALGORITHM_TYPE_SHA256_RSA8192 as u32,
    ];
    const SHA512_ALGOES: [u32; 3] = [
        AvbAlgorithmType::AVB_ALGORITHM_TYPE_SHA512_RSA2048 as u32,
        AvbAlgorithmType::AVB_ALGORITHM_TYPE_SHA512_RSA4096 as u32,
        AvbAlgorithmType::AVB_ALGORITHM_TYPE_SHA512_RSA8192 as u32,
    ];
    let algo_type = header.algorithm_type;
    let mut hash_context = if SHA256_ALGOES.contains(&algo_type) {
        digest::Context::new(&digest::SHA256)
    } else if SHA512_ALGOES.contains(&algo_type) {
        digest::Context::new(&digest::SHA512)
    } else {
        panic!("Unknown algorithm type: {}", algo_type);
    };

    // VBMeta = AvbVBMetaImageHeader + Authentication data + Auxiliary data
    // Authentication data = hash + signature
    // Auxiliary data = descriptor + public key + publib key metadata
    let authentication_data_offset = header_offset as usize + HEADER_SIZE;
    let auxiliary_data_offset =
        authentication_data_offset + header.authentication_data_block_size as usize;
    let auxiliary_data_size = header.auxiliary_data_block_size as usize;

    f.seek(std::io::SeekFrom::Start(authentication_data_offset as u64))?;
    let mut authentication_data = vec![0; auxiliary_data_size];
    f.read_exact(&mut authentication_data)?;

    f.seek(std::io::SeekFrom::Start(auxiliary_data_offset as u64))?;
    let mut auxiliary_data = vec![0; auxiliary_data_size];
    f.read_exact(&mut auxiliary_data)?;

    let mut message = header_buf[0..HEADER_SIZE].to_vec();
    message.extend(&auxiliary_data);
    hash_context.update(&message);
    let hash_calc = hash_context.finish();
    let hash_calc = hash_calc.as_ref();
    println!("{:#?}", hex(hash_calc));

    let hash = &authentication_data
        [header.hash_offset as usize..header.hash_offset as usize + header.hash_size as usize];
    println!("{:#?}", hex(hash));

    let vbmeta_hash_matches = hash_calc == hash;
    if hash_calc == hash {
        println!("Hash matches");
    }

    let auth_data_size = header.authentication_data_block_size;
    let pubkey_size = header.public_key_size;
    let pubkey_offset = header.public_key_offset;
    println!(
        "auth data size: {} {} {}",
        auth_data_size, pubkey_offset, pubkey_size
    );
    let public_key_data = &auxiliary_data[header.public_key_offset as usize
        ..header.public_key_offset as usize + header.public_key_size as usize];
    let public_key_header = public_key_data.as_ptr() as *const AvbRSAPublicKeyHeader;
    let pubkey_header_size = std::mem::size_of::<AvbRSAPublicKeyHeader>();
    let num_bits = unsafe { (*public_key_header).key_num_bits.to_be() };
    println!("key num bits: {} n0inv: {}", num_bits, unsafe {
        (*public_key_header).n0inv.to_be()
    });
    let modulus = &public_key_data[pubkey_header_size..pubkey_header_size + num_bits as usize / 8];
    println!("modulus: {}", hex(modulus));

    let n = BigUint::from_bytes_be(modulus);
    let e = BigUint::from(PUBLIC_EXPONENT);
    let pubkey = RsaPublicKey::new(n, e)?;

    let verifying_key = VerifyingKey::<rsa::sha2::Sha256>::new(pubkey);

    let mut vbmeta_signature_correct = false;
    let sig_value = &authentication_data[header.signature_offset as usize
        ..header.signature_offset as usize + header.signature_size as usize];
    let signature = rsa::pkcs1v15::Signature::try_from(sig_value)?;
    match verifying_key.verify_prehash(hash, &signature) {
        Ok(_) => {
            println!("Verify Ok");
            vbmeta_signature_correct = true;
        }
        Err(e) => {
            println!("Verify Failed: {e}");
        }
    }
    let testkey = if num_bits == 2048 {
        TESTKEY_2048
    } else if num_bits == 4096 {
        TESTKEY_4096
    } else {
        return Err("Unknown rsa key size: {num_bits}".into());
    };

    let testkey = RsaPrivateKey::from_pkcs1_pem(String::from_utf8(testkey.to_vec())?.as_str())?;
    let signing_key = SigningKey::<Sha256>::new(testkey.clone());

    let new_signature = signing_key.sign_prehash(hash_calc)?.to_bytes();

    let descriptors_data = &auxiliary_data[header.descriptors_offset as usize
        ..header.descriptors_offset as usize + header.descriptors_size as usize];

    f.seek(std::io::SeekFrom::Start(0))?;
    let mut image_data = vec![0; original_image_size as usize];
    f.read_exact(&mut image_data)?;

    let mut partition_hash_matches = false;
    let mut pos = 0;
    let mut new_descriptors_data = vec![];
    while pos < descriptors_data.len() {
        let descriptor_header = (&descriptors_data[pos..]).as_ptr() as *const AvbDescriptor;
        let descriptor_header_size = std::mem::size_of::<AvbDescriptor>();
        let tag = unsafe { (*descriptor_header).tag.to_be() };
        let num_bytes_following = unsafe { (*descriptor_header).num_bytes_following.to_be() };
        println!(
            "descriptor tag: {} num_bytes_following: {}",
            tag, num_bytes_following
        );

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
                return Err("Invalid hash descriptor".into());
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
            println!("algo: {}", algo_name);
            println!(
                "partition name: {}",
                String::from_utf8_lossy(partition_name)
            );
            println!("salt: {}", hex(salt));
            println!("digest: {}", hex(digest));

            let hash_partition_calc = if original_image_size != 0 {
                let mut hash_context = if algo_name == "sha256" {
                    digest::Context::new(&digest::SHA256)
                } else if algo_name == "sha512" {
                    digest::Context::new(&digest::SHA512)
                } else {
                    return Err("Unknown digest algorithm".into());
                };
                hash_context.update(&salt);
                hash_context.update(&image_data);
                let hash_partition_calc = hash_context.finish();
                let hash_partition_calc = hash_partition_calc.as_ref().to_owned();
                println!("{:#?}", hex(&hash_partition_calc));
                if hash_partition_calc == digest {
                    println!("Partition hash matches");
                    partition_hash_matches = true;
                } else {
                    return Err("Hash does not match".into());
                }
                hash_partition_calc
            } else {
                return Err("Not supported now".into());
            };
            new_descriptors_data.extend_from_slice(unsafe {
                std::slice::from_raw_parts(
                    hash_descriptor as *const AvbHashDescriptor as *const u8,
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

    if vbmeta_hash_matches && vbmeta_signature_correct && partition_hash_matches {
        println!("Hash and signature are all okay.");
    }

    let mut new_header = header.clone();
    let testpubkey = testkey.to_public_key();
    let num_key_bytes = num_bits as usize / 8;

    let modulus_bytes = to_fixed_length(&testpubkey.n(), num_key_bytes)?;

    let n_signed = BigInt::from_biguint(num_bigint_dig::Sign::Plus, testpubkey.n().clone());
    let r = BigInt::one() << 32;
    let egcd = n_signed.extended_gcd(&r);

    println!("egcd: {:?}", egcd);
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
            None => return Err("Failed to calculate n0inv".into()),
        },
        None => return Err("Failed to calculate n0inv".into()),
    };
    let mut pubkey_header = AvbRSAPublicKeyHeader::default();
    pubkey_header.key_num_bits = num_bits;
    pubkey_header.n0inv = n0inv;
    println!("Calculated n0inv: {}", n0inv);

    let two = BigUint::from(2u8);
    let exponent = BigUint::from(2 * num_bits);

    let rr = two.modpow(&exponent, testpubkey.n());
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

    new_header.hash_offset = 0;
    new_header.hash_size = if SHA256_ALGOES.contains(&algo_type) {
        32
    } else {
        64
    };
    new_header.signature_offset = new_header.hash_size;
    new_header.signature_size = new_signature.len() as u64;

    new_header.authentication_data_block_size =
        new_header.signature_offset + new_header.signature_size;
    const VBMETA_ALIGN: usize = 64;
    new_header.authentication_data_block_size += pad_size(new_header.authentication_data_block_size as usize, VBMETA_ALIGN) as u64;

    new_header.descriptors_offset = 0;
    new_header.descriptors_size = new_descriptors_data.len() as u64;
    new_header.public_key_offset = new_header.descriptors_offset + new_header.descriptors_size;
    new_header.public_key_size = pubkey_bytes.len() as u64;
    new_header.public_key_metadata_offset = new_header.public_key_offset + new_header.public_key_size;
    new_header.public_key_metadata_size = 0;

    new_header.auxiliary_data_block_size =
        new_header.public_key_metadata_offset + new_header.public_key_metadata_size;
    new_header.auxiliary_data_block_size += pad_size(new_header.auxiliary_data_block_size as usize, VBMETA_ALIGN) as u64;

    let mut new_header_dest = unsafe { std::mem::zeroed::<AvbVBMetaImageHeader>() };
    avb_vbmeta_image_header_to_host_byte_order(&new_header, &mut new_header_dest);

    let mut vbmeta_bytes = vec![];
    vbmeta_bytes.extend_from_slice(unsafe {
        std::slice::from_raw_parts(
            &new_header_dest as *const AvbVBMetaImageHeader as *const u8,
            std::mem::size_of::<AvbVBMetaImageHeader>(),
        )
    });
    vbmeta_bytes.extend(hash_calc);
    vbmeta_bytes.extend(new_signature);
    pad_right(&mut vbmeta_bytes, VBMETA_ALIGN);
    vbmeta_bytes.extend(new_descriptors_data);
    vbmeta_bytes.extend(pubkey_bytes);
    pad_right(&mut vbmeta_bytes, VBMETA_ALIGN);

    let mut footer = unsafe { std::mem::zeroed::<AvbFooter>() };
    footer.magic = *b"AVBf";
    footer.original_image_size = original_image_size;
    footer.vbmeta_offset = original_image_size;
    footer.vbmeta_size = vbmeta_bytes.len() as u64;
    footer.version_major = 1;
    footer.version_minor = 0;
    let mut footer_dest = unsafe { std::mem::zeroed::<AvbFooter>() };
    avb_footer_to_host_byte_order(&footer, &mut footer_dest);

    drop(f);

    let mut f = std::fs::File::create("bootout.img")?;
    f.write_all(&image_data)?;
    f.write_all(&vbmeta_bytes)?;
    f.seek(std::io::SeekFrom::Start((filesize - FOOTER_SIZE) as u64))?;
    f.write_all(unsafe { std::slice::from_raw_parts(&footer_dest as *const AvbFooter as *const u8, FOOTER_SIZE) })?;


    Ok(())
}
