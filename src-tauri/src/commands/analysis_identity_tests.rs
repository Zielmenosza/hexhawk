//! Actual native checked handlers; original legacy-adapter RED is archived.
use super::{disassemble, fixtures::fixture, graph, hex, inspect};
use super::super::analysis_bound;
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT: AtomicU64 = AtomicU64::new(0);
fn changed_input(test: impl FnOnce(String, String)) {
    let _guard = analysis_bound::TEST_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let path = std::env::temp_dir().join(format!("hh-identity-{}-{}.bin",std::process::id(),NEXT.fetch_add(1,Ordering::SeqCst)));
    let mut data=fixture(0,0,0,1);
    data[0x96..0x98].copy_from_slice(&0x22u16.to_le_bytes()); // executable image
    let marker=b"AAA_EVIDENCE\0";
    data[0x17000..0x17000+marker.len()].copy_from_slice(marker);
    data[0x17020..0x17030].fill(0x90);
    std::fs::write(&path,&data).unwrap();
    let p=path.to_string_lossy().into_owned();
    let sha=inspect::inspect_file_metadata(p.clone()).unwrap().sha256;
    data[0x17000]=b'B';data[0x17020]=0xc3;
    std::fs::write(&path,data).unwrap();
    assert_ne!(inspect::inspect_file_metadata(p.clone()).unwrap().sha256,sha);
    test(p,sha);
    std::fs::remove_file(path).unwrap();
}
fn strings_for_identity(path:String,expected:String)->Result<Vec<hex::StringMatch>,String>{analysis_bound::find_strings(path,0x17000,32,1,expected)}
fn disassembly_for_identity(path:String,expected:String)->Result<disassemble::DisassemblyResult,String>{analysis_bound::disassemble_file_range(path,0x17020,16,Some(8),expected)}
fn cfg_for_identity(path:String,expected:String)->Result<graph::CfgGraph,String>{analysis_bound::build_cfg(path,0x17020,16,expected)}
fn extras_for_identity(path:String,expected:String)->Result<inspect::PeExtras,String>{analysis_bound::inspect_pe_extras(path,expected)}
#[test]
fn same_path_strings_cannot_silently_use_a_different_inspected_identity(){changed_input(|p,sha|assert!(strings_for_identity(p,sha).is_err(),"changed bytes must not earn old strings identity"));}
#[test]
fn same_path_disassembly_cannot_silently_use_a_different_inspected_identity(){changed_input(|p,sha|assert!(disassembly_for_identity(p,sha).is_err(),"changed bytes must not earn old disassembly identity"));}
#[test]
fn same_path_cfg_cannot_silently_use_a_different_inspected_identity(){changed_input(|p,sha|assert!(cfg_for_identity(p,sha).is_err(),"changed bytes must not earn old CFG identity"));}
#[test]
fn same_path_extras_cannot_silently_use_a_different_inspected_identity(){changed_input(|p,sha|assert!(extras_for_identity(p,sha).is_err(),"changed bytes must not earn old inspection extras identity"));}

#[test]
fn unchanged_identity_accepts_all_native_analysis_handlers() {
    changed_input(|path,_old_sha| {
        let sha=analysis_bound::inspect_file_metadata(path.clone()).unwrap().sha256;
        let strings=strings_for_identity(path.clone(),sha.clone()).unwrap();
        assert_eq!(strings[0].text,"BAA_EVIDENCE");
        let instructions=disassembly_for_identity(path.clone(),sha.clone()).unwrap();
        assert_eq!(instructions.instructions[0].mnemonic,"ret");
        assert!(cfg_for_identity(path.clone(),sha.clone()).is_ok());
        assert!(extras_for_identity(path.clone(),sha.clone()).is_ok());
        assert_eq!(analysis_bound::read_hex_range(path.clone(),0x17020,1,sha.clone()).unwrap(),vec![0xc3]);
        assert!(analysis_bound::inspect_macho_load_commands(path,sha.to_uppercase()).unwrap().is_empty());
    });
}

#[test]
fn changed_identity_is_rejected_by_hex_and_macho_auxiliary_handlers() {
    changed_input(|path,sha| {
        assert!(analysis_bound::read_hex_range(path.clone(),0,16,sha.clone()).unwrap_err().contains("identity changed"));
        assert!(analysis_bound::inspect_macho_load_commands(path,sha).unwrap_err().contains("identity changed"));
    });
}

#[test]
fn operation_parses_owned_bytes_even_when_path_changes_after_verification() {
    changed_input(|path,_old_sha| {
        let sha=analysis_bound::inspect_file_metadata(path.clone()).unwrap().sha256;
        analysis_bound::with_identity(&path,&sha,|snapshot| {
            let mut replacement=snapshot.to_vec();replacement[0x17000]=b'C';
            std::fs::write(&path,replacement).unwrap();
            let strings=hex::find_strings_in_bytes(&snapshot[0x17000..0x17020],1,0x17000)?;
            assert_eq!(strings[0].text,"BAA_EVIDENCE");
            assert_ne!(inspect::inspect_file_metadata(path.clone()).unwrap().sha256,sha);
            Ok(())
        }).unwrap();
    });
}

#[test]
fn native_admission_stays_bounded_and_releases_after_errors() {
    let _guard=analysis_bound::TEST_SERIAL.lock().unwrap_or_else(|e|e.into_inner());
    fn nested(depth:usize)->Result<(),String>{analysis_bound::with_admission(||if depth==0{Ok(())}else{nested(depth-1)})}
    assert!(nested(4).unwrap_err().contains("maximum four"));
    assert!(nested(3).is_ok());
    assert!(analysis_bound::with_identity("absent-file","bad-digest",|_|Ok(())).unwrap_err().contains("SHA-256"));
    assert!(nested(3).is_ok());
}

#[test]
fn checked_handlers_reject_invalid_ranges_before_opening_a_path() {
    let _guard=analysis_bound::TEST_SERIAL.lock().unwrap_or_else(|e|e.into_inner());
    let sha="a".repeat(64);
    assert!(analysis_bound::find_strings("absent-file".into(),usize::MAX,1,1,sha.clone()).unwrap_err().contains("overflow"));
    assert!(analysis_bound::disassemble_file_range("absent-file".into(),0,1,Some(16_385),sha.clone()).unwrap_err().contains("instruction budget"));
    assert!(analysis_bound::build_cfg("absent-file".into(),0,256*1024+1,sha.clone()).unwrap_err().contains("byte budget"));
    assert!(analysis_bound::read_hex_range("absent-file".into(),u64::MAX,1,sha).unwrap_err().contains("overflow"));
}

mod release_scope {
    use super::*;
    use object::Object;
    use sha2::{Digest, Sha256};

    fn w16(d: &mut [u8], at: usize, value: u16) { d[at..at+2].copy_from_slice(&value.to_le_bytes()); }
    fn w32(d: &mut [u8], at: usize, value: u32) { d[at..at+4].copy_from_slice(&value.to_le_bytes()); }

    // Authored inert, structurally parseable images, not compiler-built programs.
    // Both widths carry file-backed evidence and real x86 decoder input; never executed.
    fn pe(pe64: bool, dll: bool) -> Vec<u8> {
        let mut d = fixture(0, 0, 0, 1);
        w16(&mut d, 0x96, 0x22 | if dll { 0x2000 } else { 0 });
        if !pe64 {
            d.copy_within(0x188..0x1b0, 0x178);
            d[0x98..0x178].fill(0);
            w16(&mut d, 0x84, 0x14c);
            w16(&mut d, 0x94, 0xe0);
            w16(&mut d, 0x98, 0x10b);
            w32(&mut d, 0x98+28, 0x400000);
            w32(&mut d, 0x98+60, 0x200);
            w32(&mut d, 0x98+92, 16);
        }
        d[0x17000..0x17010].copy_from_slice(b"SCOPE_EVIDENCE\0\0");
        d[0x17020..0x17023].copy_from_slice(&[0x48, 0x90, 0xc3]);
        d
    }
    fn elf() -> Vec<u8> {
        let mut d = vec![0; 64];
        d[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        w16(&mut d, 16, 2); // ET_EXEC
        w16(&mut d, 18, 62); // EM_X86_64
        w32(&mut d, 20, 1);
        w16(&mut d, 52, 64);
        w16(&mut d, 54, 56);
        w16(&mut d, 58, 64);
        d
    }
    fn macho() -> Vec<u8> {
        let mut d = vec![0; 32];
        w32(&mut d, 0, 0xfeedfacf);
        w32(&mut d, 4, 0x01000007); // CPU_TYPE_X86_64
        w32(&mut d, 8, 3);
        w32(&mut d, 12, 2); // MH_EXECUTE, no load commands
        d
    }
    struct Input(std::path::PathBuf);
    impl Drop for Input { fn drop(&mut self) { let _ = std::fs::remove_file(&self.0); } }
    fn input<T>(d: &[u8], f: impl FnOnce(String, String) -> T) -> T {
        let _guard = analysis_bound::TEST_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let file = Input(std::env::temp_dir().join(format!("hh-release-scope-{}-{}.bin", std::process::id(), NEXT.fetch_add(1, Ordering::SeqCst))));
        std::fs::write(&file.0, d).unwrap();
        f(file.0.to_string_lossy().into_owned(), format!("{:x}", Sha256::digest(d)))
    }
    fn reject(d: &[u8]) -> Vec<String> {
        input(d, |p, sha| {
            // Invoke each registered checked handler with a correct digest and valid
            // request bounds. Collect every result so one early failure cannot mask a bypass.
            let results = [
                ("metadata", analysis_bound::inspect_file_metadata(p.clone()).map(|_| ())),
                ("extras", analysis_bound::inspect_pe_extras(p.clone(), sha.clone()).map(|_| ())),
                ("hex", analysis_bound::read_hex_range(p.clone(), 0, 16, sha.clone()).map(|_| ())),
                ("strings", analysis_bound::find_strings(p.clone(), 0, 16, 1, sha.clone()).map(|_| ())),
                ("disassembly", analysis_bound::disassemble_file_range(p.clone(), 0, 16, Some(8), sha.clone()).map(|_| ())),
                ("cfg", analysis_bound::build_cfg(p, 0, 16, sha).map(|_| ())),
            ];
            results.into_iter().filter_map(|(name, result)| match result {
                Ok(()) => Some(format!("{name}: out-of-scope input accepted")),
                Err(error) if error.contains("Windows first release") && error.contains("PE32/x86") && error.contains("PE32+/x64") => None,
                Err(error) => Some(format!("{name}: no explicit release-scope rejection: {error}")),
            }).collect()
        })
    }
    fn reject_all(cases: &[Vec<u8>]) {
        let failures: Vec<_> = cases.iter().enumerate().flat_map(|(i, d)| {
            reject(d).into_iter().map(move |e| format!("case {i} ({} bytes): {e}", d.len()))
        }).collect();
        assert!(failures.is_empty(), "checked release-scope failures: {failures:#?}");
    }
    fn json(v: impl serde::Serialize) -> serde_json::Value { serde_json::to_value(v).unwrap() }

    #[test]
    fn supported_pe32_x86_and_pe64_x64_exe_dll_preserve_outputs() {
        for pe64 in [false, true] {
            for dll in [false, true] {
                input(&pe(pe64, dll), |p, sha| {
                    let m = analysis_bound::inspect_file_metadata(p.clone()).unwrap();
                    assert_eq!(m.file_type, "Pe");
                    assert_eq!(m.architecture, if pe64 { "x64" } else { "x86" });
                    assert_eq!(m.sha256, sha);
                    assert_eq!(m.image_base, if pe64 { 0x140000000 } else { 0x400000 });
                    assert_eq!(json(&m), json(inspect::inspect_file_metadata(p.clone()).unwrap()));
                    assert_eq!(json(analysis_bound::inspect_pe_extras(p.clone(), sha.clone()).unwrap()), json(inspect::inspect_pe_extras(p.clone()).unwrap()));
                    assert_eq!(analysis_bound::read_hex_range(p.clone(), 0x17020, 3, sha.clone()).unwrap(), [0x48, 0x90, 0xc3]);
                    let strings = analysis_bound::find_strings(p.clone(), 0x17000, 16, 1, sha.clone()).unwrap();
                    assert_eq!(strings[0].text, "SCOPE_EVIDENCE");
                    let dis = analysis_bound::disassemble_file_range(p.clone(), 0x17020, 3, Some(8), sha.clone()).unwrap();
                    assert_eq!(dis.arch, if pe64 { "x86-64" } else { "x86" });
                    assert!(!dis.is_fallback);
                    assert_eq!(dis.instructions[0].mnemonic, if pe64 { "nop" } else { "dec" });
                    assert_eq!(json(dis), json(disassemble::disassemble_file_range(p.clone(), 0x17020, 3, Some(8)).unwrap()));
                    assert_eq!(json(analysis_bound::build_cfg(p.clone(), 0x17020, 3, sha).unwrap()), json(graph::build_cfg(p, 0x17020, 3).unwrap()));
                });
            }
        }
    }
    #[test]
    fn rejects_real_elf_and_macho_without_changing_legacy_inspection() {
        let cases = [elf(), macho()];
        for (d, format) in cases.iter().zip([object::BinaryFormat::Elf, object::BinaryFormat::MachO]) {
            let parsed = object::File::parse(d.as_slice()).unwrap();
            assert_eq!(parsed.format(), format);
            assert_eq!(parsed.architecture(), object::Architecture::X86_64);
            input(d, |p, _| assert_eq!(inspect::inspect_file_metadata(p).unwrap().architecture, "x64"));
        }
        input(b"plain inert data", |p, _| {
            assert_eq!(inspect::inspect_file_metadata(p.clone()).unwrap().sections.len(), 1);
            assert_eq!(inspect::read_inspection_snapshot(&p).unwrap(), b"plain inert data");
        });
        reject_all(&cases);
    }
    #[test]
    fn rejects_arm_and_arm64_pe_before_native_decoders() {
        let mut cases = Vec::new();
        // object 0.31 maps ARMNT, not the older ARM machine code, to Arm.
        for (pe64, machine, arch) in [(false, 0x1c0, object::Architecture::Unknown), (false, 0x1c4, object::Architecture::Arm), (true, 0xaa64, object::Architecture::Aarch64)] {
            let mut d = pe(pe64, false);
            w16(&mut d, 0x84, machine);
            let parsed = object::File::parse(d.as_slice()).unwrap();
            assert_eq!(parsed.format(), object::BinaryFormat::Pe);
            assert_eq!(parsed.architecture(), arch);
            cases.push(d);
        }
        reject_all(&cases);
    }
    #[test]
    fn rejects_crossed_machine_and_optional_header_widths() {
        let cases: Vec<_> = [false, true].into_iter().map(|pe64| {
            let mut d = pe(pe64, false);
            w16(&mut d, 0x84, if pe64 { 0x14c } else { 0x8664 });
            d
        }).collect();
        reject_all(&cases);
    }
    #[test]
    fn rejects_non_executable_pe_images() {
        let mut d = pe(true, false);
        w16(&mut d, 0x96, 0);
        reject_all(&[d]);
    }
    #[test]
    fn rejects_malformed_minimal_prefixes_before_hex_or_strings_evidence() {
        let mut cases = vec![vec![], b"MZ".to_vec(), b"MZnot-a-valid-PE".to_vec(), b"\x7fELF".to_vec(), b"\xcf\xfa\xed\xfe".to_vec()];
        let good = pe(true, false);
        for end in [0x3f, 0x80, 0x84, 0x97, 0x9a, 0x187, 0x1af] { cases.push(good[..end].to_vec()); }
        let mut d = good.clone(); w32(&mut d, 0x3c, u32::MAX); cases.push(d);
        let mut d = good.clone(); w32(&mut d, 0x3c, 0); cases.push(d);
        let mut d = good.clone(); d[0x80] = b'X'; cases.push(d);
        let mut d = good.clone(); w16(&mut d, 0x94, 2); cases.push(d);
        let mut d = good; w16(&mut d, 0x98, 0x107); cases.push(d);
        reject_all(&cases);
    }
}
