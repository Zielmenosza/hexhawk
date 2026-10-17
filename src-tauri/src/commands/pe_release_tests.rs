// Release-hardening regressions: authored inert inputs are never executed.
use super::{disassemble, graph, hex, inspect, pe_imports};

#[path = "analysis_identity_tests.rs"]
mod identity_contracts;

#[cfg(test)]
mod custody_tests {
    use super::pe_imports::parse_pe_imports;

    fn u16_at(bytes: &mut [u8], at: usize, value: u16) {
        bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }
    fn u32_at(bytes: &mut [u8], at: usize, value: u32) {
        bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn u64_at(bytes: &mut [u8], at: usize, value: u64) {
        bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }
    // Authored inert PE: one section is file-backed only at [0x200, 0x300).
    // The rest of this physical file must not become virtual-tail import data.
    fn fixture(dll_rva: u32, name_rva: u64) -> Vec<u8> {
        let mut data = vec![0; 0x800];
        data[..2].copy_from_slice(b"MZ");
        u32_at(&mut data, 0x3c, 0x80);
        data[0x80..0x84].copy_from_slice(b"PE\0\0");
        u16_at(&mut data, 0x84, 0x8664);
        u16_at(&mut data, 0x86, 1);
        u16_at(&mut data, 0x94, 0xf0);
        let opt = 0x98;
        u16_at(&mut data, opt, 0x20b);
        u64_at(&mut data, opt + 24, 0x140000000);
        u32_at(&mut data, opt + 60, 0x200);
        u32_at(&mut data, opt + 108, 16);
        u32_at(&mut data, opt + 120, 0x2000);
        u32_at(&mut data, opt + 124, 40);
        let section = opt + 0xf0;
        data[section..section + 6].copy_from_slice(b".rdata");
        u32_at(&mut data, section + 8, 0x1000);
        u32_at(&mut data, section + 12, 0x2000);
        u32_at(&mut data, section + 16, 0x100);
        u32_at(&mut data, section + 20, 0x200);
        u32_at(&mut data, 0x200, 0x2040);
        u32_at(&mut data, 0x20c, dll_rva);
        u32_at(&mut data, 0x210, 0x2060);
        u64_at(&mut data, 0x240, name_rva);
        data[0x270..0x27c].copy_from_slice(b"BACKED.dll\0\0");
        data[0x282..0x28c].copy_from_slice(b"KnownName\0");
        data[0x300..0x30d].copy_from_slice(b"UNBACKED.dll\0");
        data[0x312..0x324].copy_from_slice(b"UNBACKED_FUNCTION\0");
        data
    }

    #[test]
    fn never_fabricates_dll_name_from_virtual_tail_or_overlay() {
        let result = parse_pe_imports(&fixture(0x2100, 0x2080));
        assert!(result.is_err(), "unbacked DLL must fail closed");
        let imports = result.unwrap_or_default();
        assert!(imports.iter().all(|entry| entry.dll != "UNBACKED.dll"),
            "parser promoted physically present but non-section-backed bytes to DLL evidence");
    }

    #[test]
    fn never_fabricates_function_name_from_virtual_tail_or_overlay() {
        let result = parse_pe_imports(&fixture(0x2070, 0x2110));
        assert!(result.is_err(), "unbacked function must fail closed");
        let imports = result.unwrap_or_default();
        assert!(imports.iter().all(|entry| entry.name.as_deref() != Some("UNBACKED_FUNCTION")),
            "parser promoted non-section-backed bytes to named-import evidence");
    }
}

#[cfg(test)]
mod fixtures {
    fn w16(d: &mut [u8], p: usize, v: u16) { d[p..p+2].copy_from_slice(&v.to_le_bytes()); }
    fn w32(d: &mut [u8], p: usize, v: u32) { d[p..p+4].copy_from_slice(&v.to_le_bytes()); }
    fn w64(d: &mut [u8], p: usize, v: u64) { d[p..p+8].copy_from_slice(&v.to_le_bytes()); }
    const SECTION: usize = 0x188;
    fn rva(offset: usize) -> u32 { (offset + 0x1e00) as u32 }
    pub fn fixture(desc: usize, thunks: usize, name_len: usize, dll_len: usize) -> Vec<u8> {
        let mut d=vec![0;0x20000];
        d[..2].copy_from_slice(b"MZ"); w32(&mut d,0x3c,0x80); d[0x80..0x84].copy_from_slice(b"PE\0\0");
        w16(&mut d,0x84,0x8664); w16(&mut d,0x86,1); w16(&mut d,0x94,0xf0); w16(&mut d,0x98,0x20b);
        w64(&mut d,0xb0,0x140000000); w32(&mut d,0x98+60,0x200); w32(&mut d,0x98+108,16);
        w32(&mut d,0x98+120,rva(0x200)); w32(&mut d,0x98+124,((desc+1)*20) as u32);
        w32(&mut d,SECTION+8,0x30000); w32(&mut d,SECTION+12,0x2000); w32(&mut d,SECTION+16,0x1fe00); w32(&mut d,SECTION+20,0x200);
        for i in 0..desc { w32(&mut d,0x200+i*20,rva(0x2000)); w32(&mut d,0x20c+i*20,rva(0x1e000)); w32(&mut d,0x210+i*20,rva(0x2000)); }
        for i in 0..thunks { w64(&mut d,0x2000+i*8,if name_len==0 { 0x8000000000000007 } else { rva(0x1c000) as u64 }); }
        d[0x1c002..0x1c002+name_len].fill(b'N'); d[0x1e000..0x1e000+dll_len].fill(b'D'); d
    }

}


mod caller_tests {
use super::{inspect,disassemble};
use super::pe_imports::hardening_import_tests::fixture;
use std::sync::atomic::{AtomicU64,Ordering};
static NEXT:AtomicU64=AtomicU64::new(0);
fn input<T>(data:&[u8],test:impl FnOnce(String)->T)->T{
    let path=std::env::temp_dir().join(format!("hh-static-only-{}-{}.bin",std::process::id(),NEXT.fetch_add(1,Ordering::SeqCst)));
    std::fs::write(&path,data).unwrap();let result=test(path.to_string_lossy().into_owned());std::fs::remove_file(path).unwrap();result
}
#[test]fn inspection_propagates_import_output_budget(){
    let d=fixture(1,4096,600,4);let e=input(&d,inspect::inspect_file_metadata).unwrap_err();assert!(e.contains("output text budget"),"{e}");
}
#[test]fn disassembly_propagates_import_output_budget(){
    let d=fixture(1,4096,600,4);let e=input(&d,|p|disassemble::disassemble_file_range(p,0,16,Some(16))).unwrap_err();assert!(e.contains("output text budget"),"{e}");
}
#[test]fn inspection_legacy_import_projection_matches_named_schema(){
    let d=fixture(1,2,4,4);let m=input(&d,inspect::inspect_file_metadata).unwrap();assert_eq!(m.pe_imports.len(),2);assert_eq!(m.imports_count,2);assert_eq!(m.imports[0].name,"NNNN");assert_eq!(m.imports[0].library,"DDDD");
    let d=fixture(1,2,0,4);let m=input(&d,inspect::inspect_file_metadata).unwrap();assert_eq!(m.pe_imports.len(),2);assert_eq!(m.imports_count,0);
}
#[test]fn inspection_does_not_call_eager_export_vector(){
    let mut d=fixture(0,0,0,1);fn w(d:&mut[u8],p:usize,v:u32){d[p..p+4].copy_from_slice(&v.to_le_bytes());}
    w(&mut d,0x98+112,0x2300);w(&mut d,0x98+116,0x100);w(&mut d,0x518,u32::MAX);
    let e=input(&d,inspect::inspect_file_metadata).unwrap_err();assert!(e.contains("export entry budget"),"{e}");
}
#[test]fn extras_wrapper_propagates_raw_range_error(){
    let mut d=fixture(0,0,0,1);d[0x98+112+2*8..0x98+116+2*8].copy_from_slice(&0x25000u32.to_le_bytes());d[0x98+116+2*8..0x98+120+2*8].copy_from_slice(&0x100u32.to_le_bytes());assert!(input(&d,inspect::inspect_pe_extras).is_err());
}

}


mod adjacent_contract {
use super::inspect;
use super::fixtures::fixture;
use std::sync::atomic::{AtomicU64,Ordering};
static NEXT:AtomicU64=AtomicU64::new(0);
fn input<T>(d:&[u8],f:impl FnOnce(String)->T)->T{let p=std::env::temp_dir().join(format!("hh-adjacent-{}-{}.bin",std::process::id(),NEXT.fetch_add(1,Ordering::SeqCst)));std::fs::write(&p,d).unwrap();let result=f(p.to_string_lossy().into_owned());std::fs::remove_file(p).unwrap();result}
fn w16(d:&mut[u8],p:usize,v:u16){d[p..p+2].copy_from_slice(&v.to_le_bytes());}
fn w32(d:&mut[u8],p:usize,v:u32){d[p..p+4].copy_from_slice(&v.to_le_bytes());}
fn w64(d:&mut[u8],p:usize,v:u64){d[p..p+8].copy_from_slice(&v.to_le_bytes());}
fn rva(p:usize)->u32{(p+0x1e00)as u32}
fn resource()->Vec<u8>{let mut d=fixture(0,0,0,1);w32(&mut d,0x98+128,rva(0x500));w32(&mut d,0x98+132,0x100);w16(&mut d,0x50e,1);w32(&mut d,0x510,24);w32(&mut d,0x514,0x80000020);w16(&mut d,0x52e,1);w32(&mut d,0x530,7);w32(&mut d,0x534,0x80000040);w16(&mut d,0x54e,1);w32(&mut d,0x550,0x409);w32(&mut d,0x554,0x60);w32(&mut d,0x560,0x25000);w32(&mut d,0x564,16);d}
#[test]fn resource_virtual_tail_payload_never_becomes_evidence(){let mut d=resource();w32(&mut d,0x188+16,0x1000);assert!(input(&d,inspect::inspect_pe_extras).is_err(),"resource payload outside declared raw bytes must fail closed");}
#[test]fn resource_unmapped_payload_is_not_offset_zero(){let mut d=resource();w32(&mut d,0x560,0x7fffffff);assert!(input(&d,inspect::inspect_pe_extras).is_err(),"unmapped resource must not fabricate offset zero");}
#[test]fn resource_leaf_offset_must_respect_directory_size(){let mut d=resource();w32(&mut d,0x98+132,0x60);assert!(input(&d,inspect::inspect_pe_extras).is_err(),"leaf outside resource directory must fail closed");}
#[test]fn inspection_must_not_silently_complete_invalid_resources(){let mut d=resource();w32(&mut d,0x188+16,0x1000);assert!(input(&d,inspect::inspect_file_metadata).is_err(),"metadata must preflight extras rather than leave the UI to silently ignore their failure");}
#[test]fn tls_callback_budget_cannot_return_partial_success(){let mut d=fixture(0,0,0,1);w32(&mut d,0x98+184,rva(0x500));w32(&mut d,0x98+188,40);w64(&mut d,0x518,0x140000000+rva(0x800)as u64);for i in 0..65{w64(&mut d,0x800+i*8,0x140000000+rva(0x1000)as u64);}assert!(input(&d,inspect::inspect_pe_extras).is_err(),"TLS callback budget must fail closed, not truncate at 65 entries");}
#[test]fn tls_virtual_tail_array_cannot_be_read(){let mut d=fixture(0,0,0,1);w32(&mut d,0x188+16,0x1000);w32(&mut d,0x98+184,rva(0x500));w32(&mut d,0x98+188,40);w64(&mut d,0x518,0x140000000+rva(0x2000)as u64);w64(&mut d,0x2000,0x140000000+rva(0x900)as u64);assert!(input(&d,inspect::inspect_pe_extras).is_err(),"virtual-tail pointer array must not become TLS evidence");}

}


mod section_name_callers {
use super::{disassemble, inspect};
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT: AtomicU64 = AtomicU64::new(0);
const SINGLE: usize = 4096;
const OUTPUT: usize = 64 * 1024;
const SCAN: usize = 128 * 1024;
fn w16(d: &mut [u8], p: usize, v: u16) { d[p..p+2].copy_from_slice(&v.to_le_bytes()); }
fn w32(d: &mut [u8], p: usize, v: u32) { d[p..p+4].copy_from_slice(&v.to_le_bytes()); }
fn field(s: &[u8]) -> [u8;8] { let mut b=[0;8]; b[..s.len()].copy_from_slice(s); b }
// Authored inert PE32/PE32+: independent tiny raw sections and an optional COFF
// string table. This fixture is parsed/decoded as data, never loaded or executed.
fn fixture(pe64: bool, names: &[[u8;8]], strings: &[u8]) -> Vec<u8> {
    let opt_len=if pe64 {0xf0} else {0xe0};
    let table=0x98+opt_len;
    let headers=(table+names.len()*40+0x1ff)&!0x1ff;
    let string_start=headers+names.len()*16;
    let mut d=vec![0;string_start+4+strings.len()];
    d[..2].copy_from_slice(b"MZ"); w32(&mut d,0x3c,0x80); d[0x80..0x84].copy_from_slice(b"PE\0\0");
    w16(&mut d,0x84,if pe64 {0x8664} else {0x14c}); w16(&mut d,0x86,names.len() as u16);
    w32(&mut d,0x8c,string_start as u32); w16(&mut d,0x94,opt_len as u16);
    w16(&mut d,0x98,if pe64 {0x20b} else {0x10b});
    if pe64 { d[0xb0..0xb8].copy_from_slice(&0x140000000u64.to_le_bytes()); }
    else { w32(&mut d,0x98+28,0x400000); }
    w32(&mut d,0x98+60,headers as u32);
    for (i,name) in names.iter().enumerate() {
        let s=table+i*40; d[s..s+8].copy_from_slice(name);
        // Keep even a 96-section table below the first virtual section.
        w32(&mut d,s+8,16); w32(&mut d,s+12,0x2000+(i as u32)*0x1000);
        w32(&mut d,s+16,16); w32(&mut d,s+20,(headers+i*16) as u32);
        w32(&mut d,s+36,0x60000020); d[headers+i*16..headers+(i+1)*16].fill(0x90);
    }
    w32(&mut d,string_start,(4+strings.len()) as u32); d[string_start+4..].copy_from_slice(strings); d
}
fn aliases(count: usize, len: usize, byte: u8) -> Vec<u8> {
    let mut s=vec![byte;len]; s.push(0); fixture(true,&vec![field(b"/4");count],&s)
}
fn input<T>(d:&[u8], f:impl FnOnce(String)->T)->T {
    let p=std::env::temp_dir().join(format!("hh-section-names-{}-{}.bin",std::process::id(),NEXT.fetch_add(1,Ordering::SeqCst)));
    std::fs::write(&p,d).unwrap(); let r=f(p.to_string_lossy().into_owned()); std::fs::remove_file(p).unwrap(); r
}
fn inspect_error(d:&[u8], expected:&str) {
    let r=input(d,inspect::inspect_file_metadata);
    assert!(r.is_err(),"inspection must fail closed rather than scan/clone section-name aliases");
    let e=r.unwrap_err(); assert!(e.contains(expected),"{e}");
}
#[test] fn section_names_single_exact_and_plus_one() {
    let m=input(&aliases(1,SINGLE,b'N'),inspect::inspect_file_metadata).unwrap(); assert_eq!(m.sections[0].name,"N".repeat(SINGLE));
    inspect_error(&aliases(1,SINGLE+1,b'N'),"section individual name");
}
#[test] fn section_names_output_exact_and_plus_one_alias() {
    let m=input(&aliases(OUTPUT/SINGLE,SINGLE,b'N'),inspect::inspect_file_metadata).unwrap();
    assert_eq!(m.sections.iter().map(|s|s.name.len()).sum::<usize>(),OUTPUT);
    let mut strings=vec![b'N';SINGLE]; strings.extend_from_slice(b"\0X\0");
    let mut names=vec![field(b"/4");OUTPUT/SINGLE]; names.push(field(b"/4101"));
    inspect_error(&fixture(true,&names,&strings),"section output text");
    inspect_error(&aliases(96,SINGLE,b'N'),"section output text");
}
#[test] fn section_names_scan_exact_and_plus_one_alias() {
    // Invalid UTF-8 retains the pre-existing empty-name projection, but scanning
    // is still charged for every reference. 4095 content bytes + NUL = 4096.
    let d=aliases(SCAN/SINGLE,SINGLE-1,0xff);
    let m=input(&d,inspect::inspect_file_metadata).unwrap(); assert_eq!(m.sections.len(),32); assert!(m.sections.iter().all(|s|s.name.is_empty()));
    let mut names=vec![field(b"/4");SCAN/SINGLE]; names.push(field(b""));
    inspect_error(&fixture(true,&names,&[vec![0xff;SINGLE-1],vec![0]].concat()),"section name scan");
}
#[test] fn section_names_short_long_encodings_and_utf8_preserved() {
    for pe64 in [false,true] {
        let strings="section-λ-🦀\0.text\0".as_bytes();
        let text_offset=4+"section-λ-🦀".len()+1;
        let names=[field(b"ABCDEFGH"),field(b".text"),field(b"/4"),*b"//AAAAAE",*b"/0000004",field(format!("/{text_offset}").as_bytes()),field(b"\xff"),field(b"")];
        let d=fixture(pe64,&names,strings);
        let m=input(&d,inspect::inspect_file_metadata).unwrap();
        let expected=["ABCDEFGH",".text","section-λ-🦀","section-λ-🦀","section-λ-🦀",".text","",""];
        assert_eq!(m.sections.iter().map(|s|s.name.as_str()).collect::<Vec<_>>(),expected);
        assert_eq!(m.sections[0].file_size,16); assert_eq!(m.sections[0].virtual_size,16); assert_eq!(m.imports_count,0);
    }
    let mut s="λ".repeat(SINGLE/2).into_bytes(); s.push(0);
    let m=input(&fixture(true,&[field(b"/4")],&s),inspect::inspect_file_metadata).unwrap(); assert_eq!(m.sections[0].name.len(),SINGLE);
}
#[test] fn section_names_malformed_references_fail_closed() {
    for raw in [field(b"/bad"),*b"//AAAAA!",*b"//EAAAAA",*b"////////",field(b"/0"),field(b"/3"),field(b"/9999999"),*b"//D/////"] {
        inspect_error(&fixture(true,&[raw],b"name\0"),"section name");
    }
    let good=fixture(true,&[field(b"/4")],b"name\0");
    for (at,value) in [(0x8c,0),(0x8c,u32::MAX),(0x90,u32::MAX)] {
        let mut d=good.clone(); w32(&mut d,at,value); inspect_error(&d,"section name");
    }
    let table=u32::from_le_bytes(good[0x8c..0x90].try_into().unwrap()) as usize;
    for len in [0,1,3,u32::MAX] { let mut d=good.clone(); w32(&mut d,table,len); inspect_error(&d,"section name"); }
    inspect_error(&fixture(true,&[field(b"/4")],b"no-terminator"),"section name");
    let mut d=good.clone(); w32(&mut d,table,5); inspect_error(&d,"section name"); // physical terminator outside declared table
    let mut d=good; w32(&mut d,table,9); d.pop(); inspect_error(&d,"section name");
}
#[test] fn section_names_disassembly_rejects_amplification_at_all_offsets() {
    for offset in [0,1,usize::MAX-32] {
        let r=input(&aliases(96,SINGLE,b'N'),|p|disassemble::disassemble_file_range(p,offset,16,Some(16)));
        assert!(r.is_err(),"disassembly must preflight PE section names, including nonzero/outside offsets");
        assert!(r.unwrap_err().contains("section output text"));
    }
    let r=input(&aliases(1,SINGLE+1,b'N'),|p|disassemble::disassemble_file_range(p,0,16,Some(16)));
    assert!(r.is_err(),"disassembly must bound an individual name before object scanning");
}
#[test] fn section_names_disassembly_preserves_long_text_snap() {
    for pe64 in [false,true] {
        let d=fixture(pe64,&[field(b".data"),*b"//AAAAAE"],b".TeXt\0");
        let raw=u32::from_le_bytes(d[(if pe64 {0x188} else {0x178})+40+20..(if pe64 {0x188} else {0x178})+40+24].try_into().unwrap()) as u64;
        let r=input(&d,|p|disassemble::disassemble_file_range(p,0,16,Some(16))).unwrap();
        assert_eq!(r.instructions.len(),16); assert_eq!(r.instructions[0].address,raw); assert_eq!(r.next_byte_offset,raw+16);
    }
}
#[test] fn section_names_non_pe_fallback_unchanged() {
    let m=input(b"plain inert data",inspect::inspect_file_metadata).unwrap(); assert_eq!(m.sections.len(),1); assert!(m.sections[0].name.contains("full file"));
}
#[test] fn section_names_cfg_rejects_amplification_at_all_offsets() {
    for offset in [0, 1, usize::MAX - 32] {
        let r=input(&aliases(96,SINGLE,b'N'),|p|super::graph::build_cfg(p,offset,16));
        assert!(r.is_err(),"CFG must preflight PE section names at every offset");
        assert!(r.unwrap_err().contains("section output text"));
    }
}

}

#[cfg(test)]
mod parent_contracts {
    use super::pe_imports::{hardening_import_tests::fixture, parse_pe_exports};
    fn w16(d: &mut [u8], p: usize, v: u16) { d[p..p+2].copy_from_slice(&v.to_le_bytes()); }
    fn w32(d: &mut [u8], p: usize, v: u32) { d[p..p+4].copy_from_slice(&v.to_le_bytes()); }
    fn data_export(pe64: bool) -> Vec<u8> {
        let mut d=fixture(0,0,0,1);
        let dd=if pe64 {0x98+112} else {
            d[0x98..0x188].fill(0);
            w16(&mut d,0x98,0x10b);w32(&mut d,0x98+28,0x400000);
            w32(&mut d,0x98+60,0x200);w32(&mut d,0x98+92,16);0x98+96
        };
        w32(&mut d,dd,0x2300);w32(&mut d,dd+4,0x100);
        w32(&mut d,0x514,1);w32(&mut d,0x518,1);
        w32(&mut d,0x51c,0x2500);w32(&mut d,0x520,0x2520);w32(&mut d,0x524,0x2540);
        w32(&mut d,0x700,0x24000);w32(&mut d,0x720,0x2560);
        d[0x760..0x76f].copy_from_slice(b"ZeroFilledData\0");d
    }
    #[test]
    fn pe64_exported_zero_fill_data_keeps_table_address() {
        let e=parse_pe_exports(&data_export(true)).expect("legitimate export-data VA is not a file-byte read");
        assert_eq!(e.len(),1);assert_eq!(e[0].name,"ZeroFilledData");assert_eq!(e[0].address,0x140024000);
    }
    #[test]
    fn pe32_exported_zero_fill_data_keeps_table_address() {
        let e=parse_pe_exports(&data_export(false)).expect("PE32 zero-fill export remains valid metadata");
        assert_eq!(e.len(),1);assert_eq!(e[0].name,"ZeroFilledData");assert_eq!(e[0].address,0x424000);
    }
    #[test]
    fn export_target_outside_declared_image_regions_is_rejected() {
        let mut d=data_export(true);w32(&mut d,0x700,0x40000);assert!(parse_pe_exports(&d).is_err());
    }
    #[test]
    fn export_name_still_requires_real_file_backing() {
        let mut d=data_export(true);w32(&mut d,0x720,0x24000);assert!(parse_pe_exports(&d).is_err());
    }
}

#[cfg(test)]
mod iat_contracts {
    use super::pe_imports::{hardening_import_tests::fixture, parse_pe_imports};
    fn w16(d: &mut [u8], p: usize, v: u16) {
        d[p..p + 2].copy_from_slice(&v.to_le_bytes());
    }
    fn w32(d: &mut [u8], p: usize, v: u32) {
        d[p..p + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn bss_iat() -> Vec<u8> {
        let mut d = fixture(1, 1, 4, 4);
        w16(&mut d, 0x86, 2);
        d[0x1b0..0x1b8].copy_from_slice(b".bss\0\0\0\0");
        w32(&mut d, 0x1b0 + 8, 0x1000);
        w32(&mut d, 0x1b0 + 12, 0x40000);
        w32(&mut d, 0x1b0 + 16, 0);
        w32(&mut d, 0x1b0 + 20, 0);
        w32(&mut d, 0x1b0 + 36, 0xc0000080);
        w32(&mut d, 0x210, 0x40000);
        d
    }
    #[test]
    fn pe64_backed_lookup_can_target_raw_empty_bss_iat() {
        let entries = parse_pe_imports(&bss_iat())
            .expect("IAT destination is an address; lookup/name bytes are backed");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name.as_deref(), Some("NNNN"));
        assert_eq!(entries[0].thunk_va, 0x140040000);
    }
    #[test]
    fn pe32_backed_lookup_can_target_zero_fill_iat() {
        let mut d = fixture(1, 1, 4, 4);
        w16(&mut d, 0x84, 0x14c);
        w16(&mut d, 0x98, 0x10b);
        w32(&mut d, 0x98 + 28, 0x400000);
        w32(&mut d, 0x98 + 92, 16);
        w32(&mut d, 0x98 + 104, 0x2000);
        w32(&mut d, 0x98 + 108, 40);
        w32(&mut d, 0x2000, 0x1de00);
        w32(&mut d, 0x2004, 0);
        w32(&mut d, 0x210, 0x25000);
        w32(&mut d, 0x188 + 36, 0xc0000040);
        let entries = parse_pe_imports(&d).expect("PE32 zero-fill IAT destination is valid");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name.as_deref(), Some("NNNN"));
        assert_eq!(entries[0].thunk_va, 0x425000);
    }
    #[test]
    fn unmapped_iat_destination_remains_an_error() {
        let mut d = bss_iat();
        w32(&mut d, 0x210, 0x50000);
        assert!(parse_pe_imports(&d).is_err());
    }
    #[test]
    fn full_iat_slot_must_fit_a_single_declared_region() {
        let mut d = bss_iat();
        w32(&mut d, 0x210, 0x40ffc);
        assert!(parse_pe_imports(&d).is_err());
    }
}
