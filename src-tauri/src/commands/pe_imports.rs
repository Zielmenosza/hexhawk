use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PeImportEntry {
    /// Imported function name when the import is by name. Ordinal-only imports leave this empty.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// DLL that owns the imported function, for example KERNEL32.dll.
    pub dll: String,
    /// Import Address Table entry virtual address. This is image_base + FirstThunk[index].
    pub thunk_va: u64,
    /// Ordinal value when imported by ordinal.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ordinal: Option<u16>,
}

#[derive(Debug, Clone, Copy)]
struct PeLayout {
    image_base: u64,
    import_rva: u32,
    import_size: u32,
    is_pe64: bool,
    section_count: usize,
    sections_start: usize,
}

fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        data.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        data.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn read_u64(data: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        data.get(offset..offset + 8)?.try_into().ok()?,
    ))
}

fn read_c_string(data: &[u8], offset: usize) -> Option<String> {
    if offset >= data.len() {
        return None;
    }
    let end = data[offset..]
        .iter()
        .position(|byte| *byte == 0)
        .map(|relative| offset + relative)?;
    Some(String::from_utf8_lossy(&data[offset..end]).into_owned())
}

fn parse_layout(data: &[u8]) -> Option<PeLayout> {
    if data.len() < 0x40 || data.get(0..2) != Some(b"MZ") {
        return None;
    }
    let e_lfanew = read_u32(data, 0x3c)? as usize;
    if data.get(e_lfanew..e_lfanew + 4) != Some(b"PE\0\0") {
        return None;
    }

    let coff_start = e_lfanew + 4;
    let section_count = read_u16(data, coff_start + 2)? as usize;
    let opt_hdr_size = read_u16(data, coff_start + 16)? as usize;
    let opt_hdr_start = coff_start + 20;
    let magic = read_u16(data, opt_hdr_start)?;
    let is_pe64 = magic == 0x020b;

    let (image_base, data_directory_offset) = if is_pe64 {
        (read_u64(data, opt_hdr_start + 24)?, opt_hdr_start + 112)
    } else if magic == 0x010b {
        (
            read_u32(data, opt_hdr_start + 28)? as u64,
            opt_hdr_start + 96,
        )
    } else {
        return None;
    };

    // Data directory entry 1 is IMAGE_DIRECTORY_ENTRY_IMPORT.
    let import_directory = data_directory_offset + 8;
    let import_rva = read_u32(data, import_directory)?;
    let import_size = read_u32(data, import_directory + 4)?;
    let sections_start = opt_hdr_start + opt_hdr_size;

    Some(PeLayout {
        image_base,
        import_rva,
        import_size,
        is_pe64,
        section_count,
        sections_start,
    })
}

fn rva_to_offset(data: &[u8], layout: PeLayout, rva: u32) -> Option<usize> {
    for index in 0..layout.section_count {
        let section = layout.sections_start + index * 40;
        if section + 40 > data.len() {
            break;
        }
        let virtual_size = read_u32(data, section + 8)? as usize;
        let virtual_address = read_u32(data, section + 12)? as usize;
        let raw_size = read_u32(data, section + 16)? as usize;
        let raw_offset = read_u32(data, section + 20)? as usize;
        let span = virtual_size.max(raw_size);
        let rva = rva as usize;
        if rva >= virtual_address && rva < virtual_address + span {
            let offset = raw_offset + (rva - virtual_address);
            return (offset < data.len()).then_some(offset);
        }
    }

    None
}

/// Parse PE import table entries from raw bytes.
///
/// This parser is intentionally graceful: malformed, non-PE, or unsupported data returns an empty
/// vector so disassembly/inspection remains available as advisory evidence.
pub fn parse_pe_imports(data: &[u8]) -> Vec<PeImportEntry> {
    let Some(layout) = parse_layout(data) else {
        return vec![];
    };
    if layout.import_rva == 0 || layout.import_size == 0 {
        return vec![];
    }

    let Some(mut descriptor_offset) = rva_to_offset(data, layout, layout.import_rva) else {
        return vec![];
    };

    let mut imports = Vec::new();
    for _descriptor_index in 0..256 {
        if descriptor_offset + 20 > data.len() {
            break;
        }

        let original_first_thunk = read_u32(data, descriptor_offset).unwrap_or(0);
        let name_rva = read_u32(data, descriptor_offset + 12).unwrap_or(0);
        let first_thunk = read_u32(data, descriptor_offset + 16).unwrap_or(0);
        if original_first_thunk == 0 && name_rva == 0 && first_thunk == 0 {
            break;
        }

        let dll = name_rva
            .checked_sub(0)
            .and_then(|rva| rva_to_offset(data, layout, rva))
            .and_then(|offset| read_c_string(data, offset))
            .unwrap_or_else(|| "<unknown>".to_string());

        let thunk_table_rva = if original_first_thunk != 0 {
            original_first_thunk
        } else {
            first_thunk
        };
        if let Some(mut thunk_offset) = rva_to_offset(data, layout, thunk_table_rva) {
            let pointer_size = if layout.is_pe64 { 8usize } else { 4usize };
            for thunk_index in 0..4096usize {
                if thunk_offset + pointer_size > data.len() {
                    break;
                }
                let thunk_value = if layout.is_pe64 {
                    read_u64(data, thunk_offset).unwrap_or(0)
                } else {
                    read_u32(data, thunk_offset).unwrap_or(0) as u64
                };
                if thunk_value == 0 {
                    break;
                }

                let ordinal_mask = if layout.is_pe64 {
                    0x8000_0000_0000_0000
                } else {
                    0x8000_0000
                };
                let thunk_va =
                    layout.image_base + first_thunk as u64 + (thunk_index * pointer_size) as u64;
                if thunk_value & ordinal_mask != 0 {
                    imports.push(PeImportEntry {
                        name: None,
                        dll: dll.clone(),
                        thunk_va,
                        ordinal: Some((thunk_value & 0xffff) as u16),
                    });
                } else if let Some(name_offset) = rva_to_offset(data, layout, thunk_value as u32) {
                    let name = read_c_string(data, name_offset + 2);
                    imports.push(PeImportEntry {
                        name,
                        dll: dll.clone(),
                        thunk_va,
                        ordinal: None,
                    });
                }

                thunk_offset += pointer_size;
            }
        }

        descriptor_offset += 20;
    }

    imports
}

#[cfg(test)]
mod tests {
    use super::parse_pe_imports;

    fn put_u16(data: &mut [u8], offset: usize, value: u16) {
        data[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u32(data: &mut [u8], offset: usize, value: u32) {
        data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u64(data: &mut [u8], offset: usize, value: u64) {
        data[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn put_cstr(data: &mut [u8], offset: usize, value: &str) {
        data[offset..offset + value.len()].copy_from_slice(value.as_bytes());
        data[offset + value.len()] = 0;
    }

    fn synthetic_pe64(named: &[&str], ordinal: Option<u16>) -> Vec<u8> {
        let mut data = vec![0u8; 0x800];
        data[0..2].copy_from_slice(b"MZ");
        put_u32(&mut data, 0x3c, 0x80);
        data[0x80..0x84].copy_from_slice(b"PE\0\0");
        let coff = 0x84;
        put_u16(&mut data, coff, 0x8664);
        put_u16(&mut data, coff + 2, 1);
        put_u16(&mut data, coff + 16, 0xf0);
        let opt = coff + 20;
        put_u16(&mut data, opt, 0x20b);
        put_u64(&mut data, opt + 24, 0x140000000);
        put_u32(&mut data, opt + 112 + 8, 0x2000);
        put_u32(&mut data, opt + 112 + 12, 0x100);
        let section = opt + 0xf0;
        data[section..section + 6].copy_from_slice(b".rdata");
        put_u32(&mut data, section + 8, 0x1000);
        put_u32(&mut data, section + 12, 0x2000);
        put_u32(&mut data, section + 16, 0x600);
        put_u32(&mut data, section + 20, 0x200);

        let descriptor = 0x200;
        put_u32(&mut data, descriptor, 0x2100);
        put_u32(&mut data, descriptor + 12, 0x2200);
        put_u32(&mut data, descriptor + 16, 0x2300);
        put_cstr(&mut data, 0x400, "KERNEL32.dll");

        let mut thunk_rva = 0x2400u32;
        for (index, name) in named.iter().enumerate() {
            put_u64(&mut data, 0x300 + index * 8, thunk_rva as u64);
            put_u16(&mut data, (thunk_rva - 0x2000 + 0x200) as usize, 0);
            put_cstr(&mut data, (thunk_rva - 0x2000 + 0x200 + 2) as usize, name);
            thunk_rva += 0x40;
        }
        let mut count = named.len();
        if let Some(value) = ordinal {
            put_u64(
                &mut data,
                0x300 + count * 8,
                0x8000_0000_0000_0000 | value as u64,
            );
            count += 1;
        }
        put_u64(&mut data, 0x300 + count * 8, 0);
        data
    }

    #[test]
    fn parses_two_named_pe_imports_with_dll_and_thunk_va() {
        let imports = parse_pe_imports(&synthetic_pe64(&["CreateFileW", "CloseHandle"], None));

        assert_eq!(imports.len(), 2);
        assert_eq!(imports[0].name.as_deref(), Some("CreateFileW"));
        assert_eq!(imports[0].dll, "KERNEL32.dll");
        assert_eq!(imports[0].thunk_va, 0x140002300);
        assert_eq!(imports[1].name.as_deref(), Some("CloseHandle"));
        assert_eq!(imports[1].thunk_va, 0x140002308);
    }

    #[test]
    fn returns_empty_imports_for_non_pe_bytes() {
        assert!(parse_pe_imports(b"not a PE file").is_empty());
    }

    #[test]
    fn parses_ordinal_only_import_with_ordinal_field() {
        let imports = parse_pe_imports(&synthetic_pe64(&[], Some(7)));

        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].name, None);
        assert_eq!(imports[0].ordinal, Some(7));
        assert_eq!(imports[0].dll, "KERNEL32.dll");
    }
}
