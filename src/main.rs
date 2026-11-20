use std::env;
use std::fs;
use std::process;

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, KeyInit};
use aes::Aes256;
use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind};

fn r16(d: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([d[o], d[o + 1]])
}
fn r32(d: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([d[o], d[o + 1], d[o + 2], d[o + 3]])
}
fn w16(d: &mut [u8], o: usize, v: u16) {
    d[o..o + 2].copy_from_slice(&v.to_le_bytes());
}
fn w32(d: &mut [u8], o: usize, v: u32) {
    d[o..o + 4].copy_from_slice(&v.to_le_bytes());
}

#[derive(Clone, Debug)]
struct Section {
    name: String,
    vsize: u32,
    va: u32,
    raw_size: u32,
    raw_ptr: u32,
}

struct Pe {
    pe_off: usize,
    opt_off: usize,
    image_base: u32,
    entry_rva: u32,
    base_of_code: u32,
    section_align: u32,
    num_sections: u16,
    sec_table: usize,
    sections: Vec<Section>,
}

impl Pe {
    fn parse(data: &[u8]) -> Result<Pe, String> {
        if data.len() < 0x40 || &data[0..2] != b"MZ" {
            return Err("not MZ".into());
        }
        let pe_off = r32(data, 0x3C) as usize;
        if &data[pe_off..pe_off + 4] != b"PE\0\0" {
            return Err("not PE".into());
        }
        let machine = r16(data, pe_off + 4);
        if machine != 0x14C {
            return Err(format!("not PE32 x86 (machine 0x{:X})", machine));
        }
        let num_sections = r16(data, pe_off + 6);
        let opt_size = r16(data, pe_off + 20) as usize;
        let opt_off = pe_off + 24;
        if r16(data, opt_off) != 0x10B {
            return Err("not PE32 optional header".into());
        }
        let image_base = r32(data, opt_off + 28);
        let base_of_code = r32(data, opt_off + 20);
        let entry_rva = r32(data, opt_off + 16);
        let section_align = r32(data, opt_off + 32);
        let sec_table = opt_off + opt_size;
        let mut sections = Vec::new();
        for i in 0..num_sections as usize {
            let o = sec_table + i * 40;
            let name = String::from_utf8_lossy(&data[o..o + 8])
                .trim_end_matches('\0')
                .to_string();
            sections.push(Section {
                name,
                vsize: r32(data, o + 8),
                va: r32(data, o + 12),
                raw_size: r32(data, o + 16),
                raw_ptr: r32(data, o + 20),
            });
        }
        Ok(Pe {
            pe_off,
            opt_off,
            image_base,
            entry_rva,
            base_of_code,
            section_align,
            num_sections,
            sec_table,
            sections,
        })
    }

    fn va_to_rva(&self, va: u32) -> u32 {
        va.wrapping_sub(self.image_base)
    }

    fn rva_to_off(&self, rva: u32) -> Option<usize> {
        for s in &self.sections {
            let span = s.vsize.max(s.raw_size);
            if rva >= s.va && rva < s.va.wrapping_add(span) {
                let delta = rva - s.va;
                if delta < s.raw_size {
                    return Some((s.raw_ptr + delta) as usize);
                }
            }
        }
        None
    }

    fn section_for_rva(&self, rva: u32) -> Option<usize> {
        for (i, s) in self.sections.iter().enumerate() {
            let span = s.vsize.max(s.raw_size);
            if rva >= s.va && rva < s.va.wrapping_add(span) {
                return Some(i);
            }
        }
        None
    }
}

fn steam_xor(data: &mut [u8], size: usize, mut key: u32) -> u32 {
    let mut off = 0usize;
    if key == 0 {
        off = 4;
        key = r32(data, 0);
    }
    let mut x = off;
    while x < size {
        if x + 4 > data.len() {
            break;
        }
        let val = r32(data, x);
        w32(data, x, val ^ key);
        key = val;
        x += 4;
    }
    key
}

fn xtea_decrypt(keys: &[u32], v1: u32, v2: u32, n: u32) -> (u32, u32) {
    const DELTA: u32 = 0x9E37_79B9;
    let mut v1 = v1;
    let mut v2 = v2;
    let mut sum = DELTA.wrapping_mul(n);
    for _ in 0..n {
        v2 = v2.wrapping_sub(
            (((v1 << 4) ^ (v1 >> 5)).wrapping_add(v1))
                ^ sum.wrapping_add(keys[((sum >> 11) & 3) as usize]),
        );
        sum = sum.wrapping_sub(DELTA);
        v1 = v1.wrapping_sub(
            (((v2 << 4) ^ (v2 >> 5)).wrapping_add(v2))
                ^ sum.wrapping_add(keys[(sum & 3) as usize]),
        );
    }
    (v1, v2)
}

fn drmp_decrypt_pass1(data: &mut [u8], size: usize, keys: &[u32]) {
    let mut v1: u32 = 0x5555_5555;
    let mut v2: u32 = 0x5555_5555;
    let mut x = 0usize;
    while x + 8 <= size {
        let d1 = r32(data, x);
        let d2 = r32(data, x + 4);
        let (r1, r2) = xtea_decrypt(keys, d1, d2, 32);
        w32(data, x, r1 ^ v1);
        w32(data, x + 4, r2 ^ v2);
        v1 = d1;
        v2 = d2;
        x += 8;
    }
}

fn aes256_ecb_decrypt_block(key: &[u8], block: &[u8; 16]) -> [u8; 16] {
    let cipher = Aes256::new_from_slice(key).expect("aes key");
    let mut b = GenericArray::clone_from_slice(block);
    cipher.decrypt_block(&mut b);
    let mut out = [0u8; 16];
    out.copy_from_slice(&b);
    out
}

fn aes256_cbc_decrypt(key: &[u8], iv: [u8; 16], data: &mut [u8]) {
    let cipher = Aes256::new_from_slice(key).expect("aes key");
    let mut prev = iv;
    for chunk in data.chunks_mut(16) {
        if chunk.len() != 16 {
            break;
        }
        let mut ct = [0u8; 16];
        ct.copy_from_slice(chunk);
        let mut b = GenericArray::clone_from_slice(&ct);
        cipher.decrypt_block(&mut b);
        let mut pt = [0u8; 16];
        pt.copy_from_slice(&b);
        for i in 0..16 {
            pt[i] ^= prev[i];
        }
        chunk.copy_from_slice(&pt);
        prev = ct;
    }
}

fn is_imm(k: OpKind) -> bool {
    matches!(
        k,
        OpKind::Immediate8
            | OpKind::Immediate8to16
            | OpKind::Immediate8to32
            | OpKind::Immediate16
            | OpKind::Immediate32
    )
}

fn imm32(i: &Instruction) -> u32 {
    match i.op1_kind() {
        OpKind::Immediate8 => i.immediate8() as u32,
        OpKind::Immediate8to16 => i.immediate8to16() as u32,
        OpKind::Immediate8to32 => i.immediate8to32() as u32,
        OpKind::Immediate16 => i.immediate16() as u32,
        _ => i.immediate32(),
    }
}

fn locate_header(pe: &Pe, data: &[u8], entry_off: usize) -> Option<(u32, u32, u32)> {
    let end = (entry_off + 4096).min(data.len());
    let mut decoder =
        Decoder::with_ip(32, &data[entry_off..end], entry_off as u64, DecoderOptions::NONE);
    let mut struct_offset = 0u32;
    let mut struct_size = 0u32;
    let mut struct_xor = 0u32;
    while decoder.can_decode() {
        if struct_offset > 0 && struct_size > 0 && struct_xor > 0 {
            return Some((struct_offset, struct_size, struct_xor));
        }
        let insn = decoder.decode();
        if insn.is_invalid() {
            continue;
        }
        if insn.mnemonic() == Mnemonic::Mov {
            let k0 = insn.op0_kind();
            let k1 = insn.op1_kind();
            if k0 == OpKind::Memory && is_imm(k1) {
                let imm = imm32(&insn);
                if struct_offset == 0 {
                    struct_offset = imm.wrapping_sub(pe.image_base);
                } else {
                    struct_xor = imm;
                }
                continue;
            }
            if k0 == OpKind::Register && is_imm(k1) {
                struct_size = imm32(&insn).wrapping_mul(4);
            }
        }
    }
    if struct_offset > 0 && struct_size > 0 && struct_xor > 0 {
        Some((struct_offset, struct_size, struct_xor))
    } else {
        None
    }
}

fn parse_pattern(p: &str) -> Vec<Option<u8>> {
    p.split_whitespace()
        .map(|t| {
            if t == "??" {
                None
            } else {
                Some(u8::from_str_radix(t, 16).unwrap())
            }
        })
        .collect()
}

fn find_pattern(data: &[u8], pat: &[Option<u8>]) -> Option<usize> {
    if pat.is_empty() || data.len() < pat.len() {
        return None;
    }
    for i in 0..=(data.len() - pat.len()) {
        let mut ok = true;
        for j in 0..pat.len() {
            if let Some(b) = pat[j] {
                if data[i + j] != b {
                    ok = false;
                    break;
                }
            }
        }
        if ok {
            return Some(i);
        }
    }
    None
}

fn align_up(v: u32, a: u32) -> u32 {
    if a == 0 {
        return v;
    }
    v.div_ceil(a) * a
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let input = match args.get(1) {
        Some(v) => v.clone(),
        None => {
            eprintln!("usage: steamstub-unpacker <input.exe> [output.exe]");
            process::exit(2);
        }
    };
    let output = args
        .get(2)
        .cloned()
        .unwrap_or_else(|| format!("{}.unpacked.exe", input));

    let data = match fs::read(&input) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("[!] read failed: {e}");
            process::exit(1);
        }
    };
    println!("[*] input : {input} ({} bytes)", data.len());
    println!("[*] output: {output}");

    let pe = match Pe::parse(&data) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[!] PE parse failed: {e}");
            process::exit(1);
        }
    };
    println!(
        "[*] PE32 image_base=0x{:X} ep=0x{:X} sections={}",
        pe.image_base, pe.entry_rva, pe.num_sections
    );

    if !pe.sections.iter().any(|s| s.name == ".bind") {
        eprintln!("[!] no .bind section - not SteamStub");
        process::exit(1);
    }

    let entry_off = match pe.rva_to_off(pe.entry_rva) {
        Some(o) => o,
        None => {
            eprintln!("[!] cannot map entry RVA");
            process::exit(1);
        }
    };
    if entry_off < 4 || r32(&data, entry_off - 4) != 0xC0DE_C0DE {
        eprintln!("[!] entry signature not found (expected C0DEC0DE before EP)");
        process::exit(1);
    }
    println!("[+] SteamStub detected (entry marker C0DEC0DE)");

    let (struct_rva, struct_size, struct_xor) = match locate_header(&pe, &data, entry_off) {
        Some(v) => v,
        None => {
            eprintln!("[!] failed to locate stub header via disassembly");
            process::exit(1);
        }
    };
    println!(
        "[+] stub header: rva=0x{:X} size={} xor=0x{:X}",
        struct_rva, struct_size, struct_xor
    );

    let header_off = match pe.rva_to_off(struct_rva) {
        Some(o) => o,
        None => {
            eprintln!("[!] cannot map stub header RVA");
            process::exit(1);
        }
    };
    if header_off + struct_size as usize > data.len() {
        eprintln!("[!] stub header out of bounds");
        process::exit(1);
    }
    let mut header = data[header_off..header_off + struct_size as usize].to_vec();
    let mut xor_key = steam_xor(&mut header, struct_size as usize, 0);
    println!("[+] header decoded, rolling key=0x{:X}", xor_key);

    let d0 = (struct_size / 4) == 0xD0;
    let (pva_i, psz_i, dva_i, dsz_i, xt_i) = if d0 {
        (8usize, 9usize, 14usize, 15usize, 16usize)
    } else {
        (9usize, 10usize, 15usize, 16usize, 17usize)
    };
    let payload_va = r32(&header, pva_i * 4);
    let payload_size = r32(&header, psz_i * 4);
    let drmp_va_off = r32(&header, dva_i * 4);
    let drmp_size_off = r32(&header, dsz_i * 4);
    let xtea_off = r32(&header, xt_i * 4);
    println!(
        "[+] header variant: {}  payloadVA=0x{:X} payloadSize={}",
        if d0 { "0xD0" } else { "normal" },
        payload_va,
        payload_size
    );

    let payload_off = match pe.rva_to_off(pe.va_to_rva(payload_va)) {
        Some(o) => o,
        None => {
            eprintln!("[!] cannot map payload VA");
            process::exit(1);
        }
    };
    if payload_off + payload_size as usize > data.len() {
        eprintln!("[!] payload out of bounds");
        process::exit(1);
    }
    let mut payload = data[payload_off..payload_off + payload_size as usize].to_vec();
    xor_key = steam_xor(&mut payload, payload_size as usize, xor_key);
    println!("[+] payload decoded ({} bytes, key now 0x{:X})", payload.len(), xor_key);

    let drmp_va = r32(&payload, drmp_va_off as usize);
    let drmp_size = r32(&payload, drmp_size_off as usize) as usize;
    let drmp_off = match pe.rva_to_off(pe.va_to_rva(drmp_va)) {
        Some(o) => o,
        None => {
            eprintln!("[!] cannot map SteamDRMP VA");
            process::exit(1);
        }
    };
    if drmp_off + drmp_size > data.len() {
        eprintln!("[!] SteamDRMP out of bounds");
        process::exit(1);
    }
    let mut drmp = data[drmp_off..drmp_off + drmp_size].to_vec();
    println!("[+] SteamDRMP.dll: va=0x{:X} size={}", drmp_va, drmp_size);

    let xtea_off = xtea_off as usize;
    if xtea_off > payload.len() {
        eprintln!("[!] xtea key offset out of range");
        process::exit(1);
    }
    let key_count = (payload.len() - xtea_off) / 4;
    let mut xtea_keys = Vec::with_capacity(key_count);
    for i in 0..key_count {
        xtea_keys.push(r32(&payload, xtea_off + i * 4));
    }
    drmp_decrypt_pass1(&mut drmp, drmp_size, &xtea_keys);
    println!("[+] SteamDRMP decrypted ({} xtea keys)", xtea_keys.len());

    let p1 = parse_pattern("8B ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 8D ?? ?? ?? ?? ?? 05");
    let p2 = parse_pattern("8B ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 8B");
    let p3 = parse_pattern("8B ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? A3 ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? A3 ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? A3 ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? A3 ?? ?? ?? ?? 8B");

    let (match_off, fallback) = if let Some(o) = find_pattern(&drmp, &p1) {
        (o, false)
    } else if let Some(o) = find_pattern(&drmp, &p2) {
        (o, false)
    } else if let Some(o) = find_pattern(&drmp, &p3) {
        (o, true)
    } else {
        eprintln!("[!] failed to locate DRM offset table in SteamDRMP");
        process::exit(1);
    };
    println!(
        "[+] DRM offset table at SteamDRMP+0x{:X} (fallback={})",
        match_off, fallback
    );
    if match_off + 1024 > drmp.len() {
        eprintln!("[!] DRM offset table out of bounds");
        process::exit(1);
    }
    let block = &drmp[match_off..match_off + 1024];
    let (o0, o1, o2, o3, o4, o5, o6) = if fallback {
        (2usize, 14usize, 25usize, 36usize, 47usize, 61usize, 72usize)
    } else {
        (2usize, 14usize, 26usize, 38usize, 50usize, 62usize, 67usize)
    };
    let mut offs = [0u32; 8];
    for (i, o) in [o0, o1, o2, o3, o4, o5, o6].iter().enumerate() {
        offs[i] = r32(block, *o);
    }
    offs[7] = offs[6].wrapping_add(16);
    println!("[+] payload offsets: {:?}", offs);

    // Step 5 - decrypt main code section
    let flags = r32(&payload, offs[0] as usize);
    const NO_ENCRYPTION: u32 = 0x04;
    let cs_va = r32(&payload, offs[3] as usize);
    let cs_rva = if offs[3] != 0 {
        pe.va_to_rva(cs_va)
    } else {
        pe.base_of_code
    };
    let cs_idx = pe.section_for_rva(cs_rva).unwrap_or_else(|| {
        pe.section_for_rva(pe.base_of_code).expect("code section")
    });
    let sec = &pe.sections[cs_idx];
    println!(
        "[+] code section: {} va=0x{:X} raw=0x{:X}+0x{:X} flags=0x{:X}",
        sec.name, sec.va, sec.raw_ptr, sec.raw_size, flags
    );

    let orig_section =
        data[sec.raw_ptr as usize..(sec.raw_ptr + sec.raw_size) as usize].to_vec();
    let new_section: Vec<u8> = if flags & NO_ENCRYPTION == NO_ENCRYPTION {
        println!("[+] code section is not encrypted");
        orig_section.clone()
    } else {
        let aes_key = &payload[offs[5] as usize..offs[5] as usize + 32];
        let aes_iv = &payload[offs[6] as usize..offs[6] as usize + 16];
        let stolen = &payload[offs[7] as usize..offs[7] as usize + 16];
        let enc_size = r32(&payload, offs[4] as usize) as usize;
        println!(
            "[+] decrypting: encSize={} sectionRawSize={} stolen={:02X?}",
            enc_size, sec.raw_size, stolen
        );
        if enc_size + 16 > orig_section.len() {
            eprintln!("[!] encrypted size exceeds section raw size");
            process::exit(1);
        }
        let mut buf = vec![0u8; enc_size + 16];
        buf[0..16].copy_from_slice(stolen);
        buf[16..16 + enc_size]
            .copy_from_slice(&data[sec.raw_ptr as usize..sec.raw_ptr as usize + enc_size]);
        let mut iv = [0u8; 16];
        iv.copy_from_slice(aes_iv);
        let iv2 = aes256_ecb_decrypt_block(aes_key, &iv);
        aes256_cbc_decrypt(aes_key, iv2, &mut buf);
        let mut s = orig_section.clone();
        s[0..enc_size].copy_from_slice(&buf[0..enc_size]);
        s
    };

    // Rebuild: drop the trailing .bind section header, patch entry, truncate stub blob
    let num = pe.num_sections as usize;
    let last_kept = &pe.sections[num - 2];
    let raw_end = (last_kept.raw_ptr + last_kept.raw_size) as usize;
    let mut out = data[..raw_end].to_vec();
    out[sec.raw_ptr as usize..(sec.raw_ptr + sec.raw_size) as usize]
        .copy_from_slice(&new_section);

    let oep_va = r32(&payload, offs[2] as usize);
    let oep_rva = pe.va_to_rva(oep_va);
    w16(&mut out, pe.pe_off + 6, (num - 1) as u16);
    w32(&mut out, pe.opt_off + 16, oep_rva);
    w32(&mut out, pe.opt_off + 64, 0);
    let size_of_image = align_up(last_kept.va + last_kept.vsize, pe.section_align);
    w32(&mut out, pe.opt_off + 56, size_of_image);
    for i in 0..40 {
        out[pe.sec_table + (num - 1) * 40 + i] = 0;
    }

    println!(
        "[+] new EP RVA=0x{:X} ({}), SizeOfImage=0x{:X}, sections={}, kept {} bytes",
        oep_rva,
        sec.name,
        size_of_image,
        num - 1,
        out.len()
    );

    if let Err(e) = fs::write(&output, &out) {
        eprintln!("[!] write failed: {e}");
        process::exit(1);
    }
    println!("[+] DONE - wrote {output}");
}
