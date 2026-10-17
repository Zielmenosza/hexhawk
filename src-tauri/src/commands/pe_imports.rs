use serde::Serialize;
use std::ops::Range;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PeImportEntry {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub dll: String,
    pub thunk_va: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ordinal: Option<u16>,
}

// Per invocation, including aliased tables/names. No partial success on exhaustion.
pub const MAX_PE_INPUT_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_PE_SECTIONS: usize = 96;
pub const MAX_PE_ENTRIES: usize = 16_384;
pub const MAX_PE_TEXT_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_PE_NAME_BYTES: usize = 4096;
pub const MAX_PE_SCAN_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_PE_STEPS: usize = 65_536;
pub const MAX_PE_DESCRIPTORS: usize = 256;
pub const MAX_PE_THUNKS: usize = 4096;
pub const MAX_PE_TLS_CALLBACKS: usize = 64;
pub const MAX_PE_RESOURCES: usize = 512;
pub const MAX_PE_SECTION_TEXT_BYTES: usize = 64 * 1024;
pub const MAX_PE_SECTION_SCAN_BYTES: usize = 128 * 1024;

type PeResult<T> = Result<T, String>;
fn malformed() -> String {
    "Malformed or non-file-backed PE metadata".into()
}
fn budget(what: &str) -> String {
    format!("PE metadata {what} budget exceeded")
}
fn bytes(data: &[u8], at: usize, len: usize) -> PeResult<&[u8]> {
    data.get(at..at.checked_add(len).ok_or_else(malformed)?)
        .ok_or_else(malformed)
}
fn u16_at(data: &[u8], at: usize) -> PeResult<u16> {
    Ok(u16::from_le_bytes(
        bytes(data, at, 2)?.try_into().map_err(|_| malformed())?,
    ))
}
fn u32_at(data: &[u8], at: usize) -> PeResult<u32> {
    Ok(u32::from_le_bytes(
        bytes(data, at, 4)?.try_into().map_err(|_| malformed())?,
    ))
}
fn u64_at(data: &[u8], at: usize) -> PeResult<u64> {
    Ok(u64::from_le_bytes(
        bytes(data, at, 8)?.try_into().map_err(|_| malformed())?,
    ))
}
fn spend(left: &mut usize, n: usize, what: &str) -> PeResult<()> {
    *left = left.checked_sub(n).ok_or_else(|| budget(what))?;
    Ok(())
}
struct Budget {
    steps: usize,
    scan: usize,
    text: usize,
    entries: usize,
}
impl Budget {
    fn new() -> Self {
        Self {
            steps: MAX_PE_STEPS,
            scan: MAX_PE_SCAN_BYTES,
            text: MAX_PE_TEXT_BYTES,
            entries: MAX_PE_ENTRIES,
        }
    }
    fn step(&mut self) -> PeResult<()> {
        spend(&mut self.steps, 1, "iteration")
    }
    fn entry(&mut self, text: usize) -> PeResult<()> {
        spend(&mut self.entries, 1, "entry")?;
        spend(&mut self.text, text, "output text")
    }
    fn name(&mut self, data: &[u8]) -> PeResult<String> {
        let limit = data.len().min(MAX_PE_NAME_BYTES + 1).min(self.scan);
        let end = data[..limit].iter().position(|b| *b == 0);
        spend(&mut self.scan, end.map_or(limit, |n| n + 1), "name scan")?;
        let end = end.ok_or_else(|| {
            if limit == 0 || self.scan == 0 {
                budget("name scan")
            } else if limit == MAX_PE_NAME_BYTES + 1 {
                budget("individual name")
            } else {
                malformed()
            }
        })?;
        // At most 3 * MAX_PE_NAME_BYTES transient lossy UTF-8 bytes.
        Ok(String::from_utf8_lossy(&data[..end]).into_owned())
    }
}
#[derive(Clone)]
struct Section {
    rva: u32,
    raw: Range<usize>,
    virtual_end: u64,
}
struct PeImage<'a> {
    data: &'a [u8],
    image_base: u64,
    is_pe64: bool,
    headers: usize,
    directories: Vec<(u32, u32)>,
    sections: Vec<Section>,
}
impl<'a> PeImage<'a> {
    fn parse(data: &'a [u8]) -> PeResult<Option<Self>> {
        if !data.starts_with(b"MZ") {
            return Ok(None);
        }
        if data.len() > MAX_PE_INPUT_BYTES {
            return Err(budget("input"));
        }
        let pe = u32_at(data, 0x3c)? as usize;
        if bytes(data, pe, 4)? != b"PE\0\0" {
            return Err(malformed());
        }
        let coff = pe.checked_add(4).ok_or_else(malformed)?;
        bytes(data, coff, 20)?;
        let count = u16_at(data, coff + 2)? as usize;
        if count > MAX_PE_SECTIONS {
            return Err(budget("section"));
        }
        let opt_size = u16_at(data, coff + 16)? as usize;
        let opt_start = coff + 20;
        let opt = bytes(data, opt_start, opt_size)?;
        let (is_pe64, dd, image_base) = match u16_at(opt, 0)? {
            0x20b => (true, 112, u64_at(opt, 24)?),
            0x10b => (false, 96, u32_at(opt, 28)? as u64),
            _ => return Err(malformed()),
        };
        let n_dirs = u32_at(opt, dd - 4)? as usize;
        if n_dirs > 16 {
            return Err(budget("directory"));
        }
        bytes(opt, dd, n_dirs * 8)?;
        let mut directories = Vec::new();
        for i in 0..n_dirs {
            directories.push((u32_at(opt, dd + i * 8)?, u32_at(opt, dd + i * 8 + 4)?));
        }
        let start = opt_start + opt_size;
        bytes(data, start, count * 40)?;
        let headers = u32_at(opt, 60)? as usize;
        if headers < start + count * 40 || headers > data.len() {
            return Err(malformed());
        }
        let mut sections: Vec<Section> = Vec::new();
        for i in 0..count {
            let s = start + i * 40;
            let rva = u32_at(data, s + 12)?;
            let raw_size = u32_at(data, s + 16)? as usize;
            let raw_start = u32_at(data, s + 20)? as usize;
            let raw_end = raw_start.checked_add(raw_size).ok_or_else(malformed)?;
            let virtual_end = rva as u64 + (u32_at(data, s + 8)? as u64).max(raw_size as u64);
            if raw_size != 0 && raw_end > data.len() {
                return Err("PE section raw extent extends beyond EOF".into());
            }
            if virtual_end > u32::MAX as u64 + 1
                || (raw_size != 0 && (raw_start < headers || (rva as usize) < headers))
            {
                return Err(malformed());
            }
            for previous in &sections {
                if (rva as u64) < previous.virtual_end && (previous.rva as u64) < virtual_end {
                    return Err(malformed());
                }
                if raw_size != 0
                    && !previous.raw.is_empty()
                    && raw_start < previous.raw.end
                    && previous.raw.start < raw_end
                {
                    return Err(malformed());
                }
            }
            sections.push(Section {
                rva,
                raw: raw_start..raw_end,
                virtual_end,
            });
        }
        Ok(Some(Self {
            data,
            image_base,
            is_pe64,
            headers,
            directories,
            sections,
        }))
    }
    fn directory(&self, index: usize) -> PeResult<Option<(u32, u32)>> {
        let (rva, size) = self.directories.get(index).copied().unwrap_or((0, 0));
        if rva == 0 && size == 0 {
            Ok(None)
        } else if rva == 0 || size == 0 {
            Err(malformed())
        } else {
            Ok(Some((rva, size)))
        }
    }
    // Return only the remainder of ONE declared raw-backed region, never a virtual tail,
    // the next section, or overlay. Every consumer also checks its full read width.
    fn span(&self, rva: u32) -> PeResult<Range<usize>> {
        if (rva as usize) < self.headers {
            return Ok(rva as usize..self.headers);
        }
        for s in &self.sections {
            if let Some(delta) = rva.checked_sub(s.rva) {
                if (delta as usize) < s.raw.len() {
                    return Ok(s.raw.start + delta as usize..s.raw.end);
                }
            }
        }
        Err(malformed())
    }
    fn range(&self, rva: u32, len: usize) -> PeResult<Range<usize>> {
        let span = self.span(rva)?;
        let end = span.start.checked_add(len).ok_or_else(malformed)?;
        if end > span.end || (rva as u64 + len as u64) > u32::MAX as u64 + 1 {
            return Err(malformed());
        }
        Ok(span.start..end)
    }
    fn at(&self, rva: u32, len: usize) -> PeResult<&'a [u8]> {
        Ok(&self.data[self.range(rva, len)?])
    }
    fn va_rva(&self, va: u64) -> PeResult<u32> {
        u32::try_from(va.checked_sub(self.image_base).ok_or_else(malformed)?)
            .map_err(|_| malformed())
    }
    // Export tables can name zero-initialized data. An exported VA is metadata,
    // not a claim that instruction/data bytes were read from the input file.
    // Keep raw-backed range() mandatory for every actual metadata byte read.
    fn declared_range(&self, rva: u32, width: usize) -> PeResult<()> {
        let end = (rva as u64)
            .checked_add(width as u64)
            .ok_or_else(malformed)?;
        if rva != 0 && width != 0 && end <= u32::MAX as u64 + 1
            && (((rva as usize) < self.headers && end <= self.headers as u64)
                || self.sections.iter().any(|s| rva >= s.rva && end <= s.virtual_end))
        {
            Ok(())
        } else {
            Err(malformed())
        }
    }
    fn declared_address(&self, rva: u32) -> PeResult<()> {
        self.declared_range(rva, 1)
    }
    fn name(&self, rva: u32, skip: usize, b: &mut Budget) -> PeResult<String> {
        let span = self.span(rva)?;
        let data = &self.data[span];
        b.name(data.get(skip..).ok_or_else(malformed)?)
    }
}

// Match COFF's fixed-width decimal and six-digit base-64 name offsets without
// resolving or scanning the potentially large string table through object.
fn section_name_offset(raw: &[u8]) -> PeResult<Option<u32>> {
    if raw[0] != b'/' {
        return Ok(None);
    }
    let mut value = 0u64;
    if raw[1] == b'/' {
        for byte in &raw[2..] {
            let digit = match byte {
                b'A'..=b'Z' => byte - b'A',
                b'a'..=b'z' => byte - b'a' + 26,
                b'0'..=b'9' => byte - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                _ => return Err(malformed()),
            };
            value = value * 64 + u64::from(digit);
        }
    } else {
        for byte in &raw[1..] {
            if *byte == 0 {
                break;
            }
            if !byte.is_ascii_digit() {
                return Err(malformed());
            }
            value = value * 10 + u64::from(byte - b'0');
        }
    }
    Ok(Some(u32::try_from(value).map_err(|_| malformed())?))
}

/// Resolve PE section names with bounded scans BEFORE object::Section::name().
/// Invalid UTF-8 keeps the existing empty-name projection, but every reference
/// still consumes scan budget. Bad offsets/unterminated names fail closed.
pub fn parse_pe_section_names(data: &[u8]) -> PeResult<Vec<String>> {
    let Some(pe) = PeImage::parse(data)? else {
        return Ok(vec![]);
    };
    let resolve = || -> PeResult<Vec<String>> {
        let coff = u32_at(data, 0x3c)? as usize + 4;
        let table = coff + 20 + u16_at(data, coff + 16)? as usize;
        let mut strings = None;
        let mut names = Vec::new();
        let mut b = Budget::new();
        b.scan = MAX_PE_SECTION_SCAN_BYTES;
        b.text = MAX_PE_SECTION_TEXT_BYTES;
        for i in 0..pe.sections.len() {
            b.step()?;
            let raw = bytes(data, table + i * 40, 8)?;
            let offset = section_name_offset(raw)?;
            let name = if let Some(offset) = offset {
                if offset < 4 {
                    return Err(malformed());
                }
                let strings = match strings {
                    Some(s) => s,
                    None => {
                        let symbols = u32_at(data, coff + 8)? as usize;
                        if symbols == 0 {
                            return Err(malformed());
                        }
                        let count = u32_at(data, coff + 12)? as usize;
                        let start = symbols.checked_add(count.checked_mul(18).ok_or_else(malformed)?)
                            .ok_or_else(malformed)?;
                        let len = u32_at(data, start)? as usize;
                        if len < 4 {
                            return Err(malformed());
                        }
                        let s = bytes(data, start, len)?;
                        strings = Some(s);
                        s
                    }
                };
                let tail = strings.get(offset as usize..).ok_or_else(malformed)?;
                let limit = tail.len().min(MAX_PE_NAME_BYTES + 1).min(b.scan);
                let end = tail[..limit].iter().position(|v| *v == 0);
                spend(&mut b.scan, end.map_or(limit, |n| n + 1), "section name scan")?;
                let end = end.ok_or_else(|| {
                    if b.scan == 0 {
                        budget("section name scan")
                    } else if limit == MAX_PE_NAME_BYTES + 1 {
                        budget("section individual name")
                    } else {
                        malformed()
                    }
                })?;
                &tail[..end]
            } else {
                let end = raw.iter().position(|v| *v == 0);
                spend(&mut b.scan, end.map_or(raw.len(), |n| n + 1), "section name scan")?;
                &raw[..end.unwrap_or(raw.len())]
            };
            let name = std::str::from_utf8(name).unwrap_or_default();
            spend(&mut b.text, name.len(), "section output text")?;
            names.try_reserve(1).map_err(|_| budget("section allocation"))?;
            names.push(name.to_owned());
        }
        Ok(names)
    };
    resolve().map_err(|e| format!("PE section name: {e}"))
}

/// Non-PE input has no PE imports. Malformed PE or budget exhaustion is an error;
/// callers MUST propagate it instead of publishing an apparently complete subset.
pub fn parse_pe_imports(data: &[u8]) -> PeResult<Vec<PeImportEntry>> {
    let Some(pe) = PeImage::parse(data)? else {
        return Ok(vec![]);
    };
    let Some((rva, size)) = pe.directory(1)? else {
        return Ok(vec![]);
    };
    let descriptors = pe.at(rva, size as usize)?;
    let mut b = Budget::new();
    let mut imports = Vec::new();
    for index in 0..=MAX_PE_DESCRIPTORS {
        b.step()?;
        let d = bytes(descriptors, index * 20, 20)?;
        if d.iter().all(|v| *v == 0) {
            return Ok(imports);
        }
        if index == MAX_PE_DESCRIPTORS {
            return Err(budget("import descriptor"));
        }
        let original = u32_at(d, 0)?;
        let first = u32_at(d, 16)?;
        if first == 0 {
            return Err(malformed());
        }
        let dll_rva = u32_at(d, 12)?;
        if dll_rva == 0 {
            return Err(malformed());
        }
        let dll = pe.name(dll_rva, 0, &mut b)?;
        if dll.is_empty() {
            return Err(malformed());
        }
        let thunk_rva = if original != 0 { original } else { first };
        let thunks = &pe.data[pe.span(thunk_rva)?];
        let width = if pe.is_pe64 { 8 } else { 4 };
        let mut terminated = false;
        for i in 0..=MAX_PE_THUNKS {
            b.step()?;
            let t = bytes(thunks, i * width, width)?;
            let value = if pe.is_pe64 {
                u64_at(t, 0)?
            } else {
                u32_at(t, 0)? as u64
            };
            if value == 0 {
                terminated = true;
                break;
            }
            if i == MAX_PE_THUNKS {
                return Err(budget("per-DLL thunk"));
            }
            // INT/name bytes must be file-backed; the loader's IAT destination
            // may be zero-filled. Validate the entire destination address slot
            // within one declared image region without inventing file bytes.
            let slot = first
                .checked_add(u32::try_from(i * width).map_err(|_| malformed())?)
                .ok_or_else(malformed)?;
            pe.declared_range(slot, width)?;
            let thunk_va = pe
                .image_base
                .checked_add(slot as u64)
                .ok_or_else(malformed)?;
            let mask = if pe.is_pe64 { 1u64 << 63 } else { 1u64 << 31 };
            let (name, ordinal) = if value & mask != 0 {
                if value & !(mask | 0xffff) != 0 {
                    return Err(malformed());
                }
                (None, Some(value as u16))
            } else {
                let name_rva = u32::try_from(value).map_err(|_| malformed())?;
                pe.at(name_rva, 2)?;
                (Some(pe.name(name_rva, 2, &mut b)?), None)
            };
            b.entry(dll.len() + name.as_ref().map_or(0, String::len))?;
            imports.try_reserve(1).map_err(|_| budget("allocation"))?;
            imports.push(PeImportEntry {
                name,
                dll: dll.clone(),
                thunk_va,
                ordinal,
            });
        }
        if !terminated {
            return Err(malformed());
        }
    }
    Err(budget("import descriptor"))
}

#[derive(Debug, Clone, Serialize)]
pub struct PeExportEntry {
    pub name: String,
    pub address: u64,
}

/// Avoid object::File::exports()'s eagerly allocated, unbudgeted PE vector.
/// Matches the existing named-export UI scope; ordinal-only exports are not listed.
pub fn parse_pe_exports(data: &[u8]) -> PeResult<Vec<PeExportEntry>> {
    let Some(pe) = PeImage::parse(data)? else {
        return Ok(vec![]);
    };
    let Some((rva, size)) = pe.directory(0)? else {
        return Ok(vec![]);
    };
    let directory = pe.at(rva, size as usize)?;
    bytes(directory, 0, 40)?;
    let functions = u32_at(directory, 20)? as usize;
    let count = u32_at(directory, 24)? as usize;
    if count > MAX_PE_ENTRIES || functions > MAX_PE_ENTRIES {
        return Err(budget("export entry"));
    }
    let addresses = pe.at(u32_at(directory, 28)?, functions * 4)?;
    let names = pe.at(u32_at(directory, 32)?, count * 4)?;
    let ordinals = pe.at(u32_at(directory, 36)?, count * 2)?;
    let mut result = Vec::new();
    let mut b = Budget::new();
    for i in 0..count {
        b.step()?;
        let ordinal = u16_at(ordinals, i * 2)? as usize;
        if ordinal >= functions {
            return Err(malformed());
        }
        let name = pe.name(u32_at(names, i * 4)?, 0, &mut b)?;
        let target = u32_at(addresses, ordinal * 4)?;
        let export_end = rva.checked_add(size).ok_or_else(malformed)?;
        if target >= rva && target < export_end {
            // Preserve object's non-forwarded named-export UI scope. Validate the
            // forwarder in the export extent, then skip it instead of inventing code evidence.
            let forwarder = pe.at(target, (export_end - target) as usize)?;
            b.name(forwarder)?;
            continue;
        } else {
            pe.declared_address(target)?;
        }
        let address = pe
            .image_base
            .checked_add(target as u64)
            .ok_or_else(malformed)?;
        b.entry(name.len())?;
        result.try_reserve(1).map_err(|_| budget("allocation"))?;
        result.push(PeExportEntry { name, address });
    }
    Ok(result)
}

#[derive(Debug, Clone, Serialize)]
pub struct TlsCallback {
    pub address: u64,
}
#[derive(Debug, Clone, Serialize)]
pub struct ResourceEntry {
    pub type_name: String,
    pub id: u32,
    pub size: u32,
    pub offset: u32,
}
#[derive(Debug, Clone, Serialize)]
pub struct PeExtras {
    pub tls_callbacks: Vec<TlsCallback>,
    pub resources: Vec<ResourceEntry>,
}

fn resource_type(id: u32) -> String {
    if id & 0x8000_0000 != 0 {
        return format!("NAMED({})", id & 0x7fff_ffff);
    }
    match id {
        1 => "RT_CURSOR".into(),
        2 => "RT_BITMAP".into(),
        3 => "RT_ICON".into(),
        4 => "RT_MENU".into(),
        5 => "RT_DIALOG".into(),
        6 => "RT_STRING".into(),
        7 => "RT_FONTDIR".into(),
        8 => "RT_FONT".into(),
        9 => "RT_ACCELERATOR".into(),
        10 => "RT_RCDATA".into(),
        11 => "RT_MESSAGETABLE".into(),
        14 => "RT_GROUP_ICON".into(),
        16 => "RT_VERSION".into(),
        24 => "RT_MANIFEST".into(),
        n => format!("RT_{n}"),
    }
}
fn resource_directory<'a>(data: &'a [u8], at: usize, b: &mut Budget) -> PeResult<&'a [u8]> {
    b.step()?;
    bytes(data, at, 16)?;
    let count = u16_at(data, at + 12)? as usize + u16_at(data, at + 14)? as usize;
    if count > MAX_PE_RESOURCES {
        return Err(budget("resource directory entry"));
    }
    bytes(data, at + 16, count * 8)
}
fn resource_name(data: &[u8], id: u32, b: &mut Budget) -> PeResult<()> {
    if id & 0x8000_0000 != 0 {
        let at = (id & 0x7fff_ffff) as usize;
        let len = u16_at(data, at)? as usize;
        if len * 2 > MAX_PE_NAME_BYTES {
            return Err(budget("resource name"));
        }
        bytes(data, at + 2, len * 2)?;
        spend(&mut b.scan, len * 2, "name scan")?;
    }
    Ok(())
}
/// All resource offsets are relative to the declared resource directory extent.
/// Walk exactly type -> ID -> language -> leaf, with global traversal/output caps.
/// Do not silently choose the first language or truncate a directory at its cap.
pub fn parse_pe_extras(data: &[u8]) -> PeResult<PeExtras> {
    let mut result = PeExtras {
        tls_callbacks: vec![],
        resources: vec![],
    };
    let Some(pe) = PeImage::parse(data)? else {
        return Ok(result);
    };
    let mut b = Budget::new();
    if let Some((rva, size)) = pe.directory(9)? {
        let d = pe.at(rva, size as usize)?;
        let width = if pe.is_pe64 { 8 } else { 4 };
        bytes(d, 0, if pe.is_pe64 { 40 } else { 24 })?;
        let callbacks = if pe.is_pe64 {
            u64_at(d, 24)?
        } else {
            u32_at(d, 12)? as u64
        };
        if callbacks != 0 {
            let array = &pe.data[pe.span(pe.va_rva(callbacks)?)?];
            for i in 0..=MAX_PE_TLS_CALLBACKS {
                b.step()?;
                let slot = bytes(array, i * width, width)?;
                let va = if pe.is_pe64 {
                    u64_at(slot, 0)?
                } else {
                    u32_at(slot, 0)? as u64
                };
                if va == 0 {
                    break;
                }
                if i == MAX_PE_TLS_CALLBACKS {
                    return Err(budget("TLS callback"));
                }
                let target = pe.va_rva(va)?;
                pe.at(target, 1)?;
                b.entry(0)?;
                result.tls_callbacks.push(TlsCallback {
                    address: target as u64,
                });
            }
        }
    }
    if let Some((rva, size)) = pe.directory(2)? {
        let tree = pe.at(rva, size as usize)?;
        let root = resource_directory(tree, 0, &mut b)?;
        for t in root.chunks_exact(8) {
            b.step()?;
            let kind = u32_at(t, 0)?;
            resource_name(tree, kind, &mut b)?;
            let type_name = resource_type(kind);
            let ptr = u32_at(t, 4)?;
            if ptr & 0x8000_0000 == 0 {
                return Err(malformed());
            }
            let ids = resource_directory(tree, (ptr & 0x7fff_ffff) as usize, &mut b)?;
            for id in ids.chunks_exact(8) {
                b.step()?;
                let id_value = u32_at(id, 0)?;
                resource_name(tree, id_value, &mut b)?;
                let ptr = u32_at(id, 4)?;
                if ptr & 0x8000_0000 == 0 {
                    return Err(malformed());
                }
                let languages = resource_directory(tree, (ptr & 0x7fff_ffff) as usize, &mut b)?;
                for lang in languages.chunks_exact(8) {
                    b.step()?;
                    resource_name(tree, u32_at(lang, 0)?, &mut b)?;
                    let ptr = u32_at(lang, 4)?;
                    if ptr & 0x8000_0000 != 0 {
                        return Err(malformed());
                    }
                    let leaf = bytes(tree, ptr as usize, 16)?;
                    let len = u32_at(leaf, 4)?;
                    let range = pe.range(u32_at(leaf, 0)?, len as usize)?;
                    if result.resources.len() == MAX_PE_RESOURCES {
                        return Err(budget("resource output"));
                    }
                    b.entry(type_name.len())?;
                    result.resources.push(ResourceEntry {
                        type_name: type_name.clone(),
                        id: id_value & 0x7fff_ffff,
                        size: len,
                        offset: u32::try_from(range.start).map_err(|_| malformed())?,
                    });
                }
            }
        }
    }
    Ok(result)
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
        put_u32(&mut data, opt + 60, 0x200);
        put_u32(&mut data, opt + 108, 16);
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
        let imports = parse_pe_imports(&synthetic_pe64(&["CreateFileW", "CloseHandle"], None))
            .expect("valid fixture");

        assert_eq!(imports.len(), 2);
        assert_eq!(imports[0].name.as_deref(), Some("CreateFileW"));
        assert_eq!(imports[0].dll, "KERNEL32.dll");
        assert_eq!(imports[0].thunk_va, 0x140002300);
        assert_eq!(imports[1].name.as_deref(), Some("CloseHandle"));
        assert_eq!(imports[1].thunk_va, 0x140002308);
    }

    #[test]
    fn returns_empty_imports_for_non_pe_bytes() {
        assert!(parse_pe_imports(b"not a PE file")
            .expect("non-PE is empty")
            .is_empty());
    }

    #[test]
    fn parses_ordinal_only_import_with_ordinal_field() {
        let imports = parse_pe_imports(&synthetic_pe64(&[], Some(7))).expect("valid fixture");

        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].name, None);
        assert_eq!(imports[0].ordinal, Some(7));
        assert_eq!(imports[0].dll, "KERNEL32.dll");
    }
}

#[cfg(test)]
pub(crate) mod hardening_import_tests {
    use super::parse_pe_imports;
    fn w16(d: &mut [u8], p: usize, v: u16) {
        d[p..p + 2].copy_from_slice(&v.to_le_bytes());
    }
    fn w32(d: &mut [u8], p: usize, v: u32) {
        d[p..p + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn w64(d: &mut [u8], p: usize, v: u64) {
        d[p..p + 8].copy_from_slice(&v.to_le_bytes());
    }
    const SECTION: usize = 0x188;
    fn rva(offset: usize) -> u32 {
        (offset + 0x1e00) as u32
    }
    pub fn fixture(desc: usize, thunks: usize, name_len: usize, dll_len: usize) -> Vec<u8> {
        let mut d = vec![0; 0x20000];
        d[..2].copy_from_slice(b"MZ");
        w32(&mut d, 0x3c, 0x80);
        d[0x80..0x84].copy_from_slice(b"PE\0\0");
        w16(&mut d, 0x84, 0x8664);
        w16(&mut d, 0x86, 1);
        w16(&mut d, 0x94, 0xf0);
        w16(&mut d, 0x98, 0x20b);
        w64(&mut d, 0xb0, 0x140000000);
        w32(&mut d, 0x98 + 60, 0x200);
        w32(&mut d, 0x98 + 108, 16);
        w32(&mut d, 0x98 + 120, rva(0x200));
        w32(&mut d, 0x98 + 124, ((desc + 1) * 20) as u32);
        w32(&mut d, SECTION + 8, 0x30000);
        w32(&mut d, SECTION + 12, 0x2000);
        w32(&mut d, SECTION + 16, 0x1fe00);
        w32(&mut d, SECTION + 20, 0x200);
        for i in 0..desc {
            w32(&mut d, 0x200 + i * 20, rva(0x2000));
            w32(&mut d, 0x20c + i * 20, rva(0x1e000));
            w32(&mut d, 0x210 + i * 20, rva(0x2000));
        }
        for i in 0..thunks {
            w64(
                &mut d,
                0x2000 + i * 8,
                if name_len == 0 {
                    0x8000000000000007
                } else {
                    rva(0x1c000) as u64
                },
            );
        }
        d[0x1c002..0x1c002 + name_len].fill(b'N');
        d[0x1e000..0x1e000 + dll_len].fill(b'D');
        d
    }
    fn error(d: &[u8]) -> String {
        parse_pe_imports(d).expect_err("must fail closed without a complete subset")
    }
    #[test]
    fn dll_string_cannot_cross_raw_end() {
        let mut d = fixture(1, 1, 4, 4);
        w32(&mut d, SECTION + 16, 0x1de04); // raw ends at 0x1e004, NUL is overlay
        error(&d);
    }
    #[test]
    fn function_string_cannot_cross_raw_end() {
        let mut d = fixture(1, 1, 4, 4);
        w32(&mut d, 0x20c, rva(0x270));
        d[0x270..0x274].copy_from_slice(b"DLL\0");
        w32(&mut d, SECTION + 16, 0x1be06);
        error(&d);
    }
    #[test]
    fn descriptor_cannot_cross_declared_directory() {
        let mut d = fixture(1, 1, 4, 4);
        w32(&mut d, 0x98 + 124, 20);
        error(&d);
    }
    #[test]
    fn descriptor_cannot_cross_raw_end() {
        let mut d = fixture(1, 1, 4, 4);
        w32(&mut d, SECTION + 16, 19);
        error(&d);
    }
    #[test]
    fn thunk_cannot_cross_raw_end() {
        let mut d = fixture(1, 1, 4, 4);
        w32(&mut d, 0x200, rva(0x1fffc));
        error(&d);
    }
    #[test]
    fn name_hint_cannot_cross_raw_end() {
        let mut d = fixture(1, 1, 4, 4);
        w64(&mut d, 0x2000, rva(0x1ffff) as u64);
        error(&d);
    }
    #[test]
    fn iat_slot_must_be_in_declared_image() {
        let mut d = fixture(1, 1, 4, 4);
        // Corrected with explicit user approval: 0x25000 was valid zero-fill,
        // while 0x40000 is outside this fixture's declared image sections.
        w32(&mut d, 0x210, 0x40000);
        error(&d);
    }
    #[test]
    fn pe64_name_rva_must_not_truncate_high_bits() {
        let mut d = fixture(1, 1, 4, 4);
        w64(&mut d, 0x2000, 0x100000000 | rva(0x1c000) as u64);
        error(&d);
    }
    #[test]
    fn individual_name_budget_is_fail_closed() {
        assert!(error(&fixture(1, 1, 4097, 4)).contains("budget"));
    }
    #[test]
    fn individual_dll_budget_is_fail_closed() {
        assert!(error(&fixture(1, 1, 4, 4097)).contains("budget"));
    }
    #[test]
    fn aliased_name_output_budget_is_global() {
        assert!(error(&fixture(1, 4096, 600, 4)).contains("output text budget"));
    }
    #[test]
    fn aliased_dll_clone_output_budget_is_global() {
        assert!(error(&fixture(1, 4096, 0, 600)).contains("output text budget"));
    }
    #[test]
    fn aliased_descriptors_share_entry_budget() {
        assert!(error(&fixture(5, 4096, 0, 1)).contains("entry budget"));
    }
    #[test]
    fn descriptor_cap_cannot_return_partial_complete() {
        assert!(error(&fixture(257, 0, 0, 1)).contains("descriptor budget"));
    }
    #[test]
    fn thunk_cap_cannot_return_partial_complete() {
        assert!(error(&fixture(1, 4097, 0, 1)).contains("thunk budget"));
    }
    #[test]
    fn exact_thunk_budget_with_terminator_is_accepted() {
        assert_eq!(
            parse_pe_imports(&fixture(1, 4096, 0, 1)).unwrap().len(),
            4096
        );
    }
    #[test]
    fn exact_descriptor_budget_with_terminator_is_accepted() {
        assert!(parse_pe_imports(&fixture(256, 0, 0, 1)).unwrap().is_empty());
    }
    #[test]
    fn exact_name_limit_is_accepted() {
        assert_eq!(
            parse_pe_imports(&fixture(1, 1, 4096, 1)).unwrap()[0]
                .name
                .as_ref()
                .unwrap()
                .len(),
            4096
        );
    }
    #[test]
    fn lossy_utf8_expansion_counts_as_output_bytes() {
        let mut d = fixture(1, 4096, 300, 1);
        d[0x1c002..0x1c002 + 300].fill(0xff);
        assert!(error(&d).contains("output text budget"));
    }
    #[test]
    fn header_backed_imports_are_allowed() {
        let mut d = fixture(1, 1, 4, 4);
        d[0x1e0..0x1e4].copy_from_slice(b"HDR\0");
        w32(&mut d, 0x20c, 0x1e0);
        assert_eq!(parse_pe_imports(&d).unwrap()[0].dll, "HDR");
    }
    #[test]
    fn malformed_optional_header_directory_extent_is_rejected() {
        let mut d = fixture(1, 1, 4, 4);
        w16(&mut d, 0x94, 112);
        error(&d);
    }
    #[test]
    fn undeclared_directories_do_not_become_evidence() {
        let mut d = fixture(1, 1, 4, 4);
        w32(&mut d, 0x98 + 108, 0);
        assert!(parse_pe_imports(&d).unwrap().is_empty());
    }
    #[test]
    fn invalid_headers_and_section_overlap_are_rejected() {
        let mut d = fixture(1, 1, 4, 4);
        w32(&mut d, 0x98 + 60, 0);
        error(&d);
        let mut d = fixture(1, 1, 4, 4);
        w16(&mut d, 0x86, 2);
        let section = d[SECTION..SECTION + 40].to_vec();
        d[SECTION + 40..SECTION + 80].copy_from_slice(&section);
        error(&d);
    }
    #[test]
    fn section_count_budget_is_explicit() {
        let mut d = fixture(1, 1, 4, 4);
        w16(&mut d, 0x86, 97);
        assert!(error(&d).contains("section budget"));
    }
}

#[cfg(test)]
mod adjacent_tests {
    use super::hardening_import_tests::fixture;
    use super::*;
    fn w16(d: &mut [u8], p: usize, v: u16) {
        d[p..p + 2].copy_from_slice(&v.to_le_bytes());
    }
    fn w32(d: &mut [u8], p: usize, v: u32) {
        d[p..p + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn w64(d: &mut [u8], p: usize, v: u64) {
        d[p..p + 8].copy_from_slice(&v.to_le_bytes());
    }
    fn rva(p: usize) -> u32 {
        (p + 0x1e00) as u32
    }
    fn dd(d: &mut [u8], i: usize, offset: usize, size: u32) {
        w32(d, 0x98 + 112 + i * 8, rva(offset));
        w32(d, 0x98 + 116 + i * 8, size);
    }
    fn tls(count: usize) -> Vec<u8> {
        let mut d = fixture(0, 0, 0, 1);
        dd(&mut d, 9, 0x500, 40);
        w64(&mut d, 0x518, 0x140000000 + rva(0x800) as u64);
        for i in 0..count {
            w64(&mut d, 0x800 + i * 8, 0x140000000 + rva(0x1000) as u64);
        }
        d
    }
    fn resources() -> Vec<u8> {
        let mut d = fixture(0, 0, 0, 1);
        dd(&mut d, 2, 0x500, 0x100);
        w16(&mut d, 0x50e, 1);
        w32(&mut d, 0x510, 24);
        w32(&mut d, 0x514, 0x80000020);
        w16(&mut d, 0x52e, 1);
        w32(&mut d, 0x530, 7);
        w32(&mut d, 0x534, 0x80000040);
        w16(&mut d, 0x54e, 1);
        w32(&mut d, 0x550, 0x409);
        w32(&mut d, 0x554, 0x60);
        w32(&mut d, 0x560, rva(0x900));
        w32(&mut d, 0x564, 16);
        d
    }
    fn exports() -> Vec<u8> {
        let mut d = fixture(0, 0, 0, 1);
        dd(&mut d, 0, 0x500, 0x100);
        w32(&mut d, 0x514, 1);
        w32(&mut d, 0x518, 1);
        w32(&mut d, 0x51c, rva(0x700));
        w32(&mut d, 0x520, rva(0x720));
        w32(&mut d, 0x524, rva(0x740));
        w32(&mut d, 0x700, rva(0x1000));
        w32(&mut d, 0x720, rva(0x760));
        d[0x760..0x767].copy_from_slice(b"Export\0");
        d
    }
    #[test]
    fn valid_tls_keeps_rva_address_schema() {
        let e = parse_pe_extras(&tls(2)).unwrap();
        assert_eq!(e.tls_callbacks.len(), 2);
        assert_eq!(e.tls_callbacks[0].address, rva(0x1000) as u64);
    }
    #[test]
    fn tls_limit_is_exact_and_overflow_is_error() {
        assert_eq!(parse_pe_extras(&tls(64)).unwrap().tls_callbacks.len(), 64);
        assert!(parse_pe_extras(&tls(65))
            .unwrap_err()
            .contains("TLS callback budget"));
    }
    #[test]
    fn tls_directory_must_be_entirely_raw_backed() {
        let mut d = tls(1);
        dd(&mut d, 9, 0x1ffff, 40);
        assert!(parse_pe_extras(&d).is_err());
    }
    #[test]
    fn tls_array_must_not_read_overlay_terminator() {
        let mut d = tls(1);
        w64(&mut d, 0x518, 0x140000000 + rva(0x1fff8) as u64);
        w64(&mut d, 0x1fff8, 0x140003000);
        assert!(parse_pe_extras(&d).is_err());
    }
    #[test]
    fn tls_va_does_not_saturate_or_truncate() {
        for va in [1, 0x240002600] {
            let mut d = tls(1);
            w64(&mut d, 0x518, va);
            assert!(parse_pe_extras(&d).is_err());
        }
    }
    #[test]
    fn tls_target_must_be_file_backed() {
        let mut d = tls(1);
        w64(&mut d, 0x800, 0x140025000);
        assert!(parse_pe_extras(&d).is_err());
    }
    #[test]
    fn tls_directory_declared_size_is_enforced() {
        let mut d = tls(1);
        dd(&mut d, 9, 0x500, 32);
        assert!(parse_pe_extras(&d).is_err());
    }
    #[test]
    fn valid_resource_leaf_is_wholly_backed() {
        let e = parse_pe_extras(&resources()).unwrap();
        assert_eq!(e.resources.len(), 1);
        assert_eq!(e.resources[0].offset, 0x900);
        assert_eq!(e.resources[0].size, 16);
        assert_eq!(e.resources[0].id, 7);
        assert_eq!(e.resources[0].type_name, "RT_MANIFEST");
    }
    #[test]
    fn resource_payload_must_not_fabricate_offset_zero() {
        let mut d = resources();
        w32(&mut d, 0x560, 0x25000);
        assert!(parse_pe_extras(&d).is_err());
    }
    #[test]
    fn resource_payload_width_must_not_cross_raw_end() {
        let mut d = resources();
        w32(&mut d, 0x560, rva(0x1fff8));
        w32(&mut d, 0x564, 16);
        assert!(parse_pe_extras(&d).is_err());
    }
    #[test]
    fn resource_leaf_offset_must_stay_inside_declared_tree() {
        let mut d = resources();
        w32(&mut d, 0x554, 0x100);
        assert!(parse_pe_extras(&d).is_err());
    }
    #[test]
    fn resource_cycle_is_rejected_by_fixed_depth() {
        let mut d = resources();
        w32(&mut d, 0x534, 0x80000020);
        assert!(parse_pe_extras(&d).is_err());
    }
    #[test]
    fn resource_directory_count_budget_is_fail_closed() {
        let mut d = resources();
        w16(&mut d, 0x50e, 513);
        assert!(parse_pe_extras(&d).unwrap_err().contains("budget"));
    }
    #[test]
    fn resource_all_languages_are_reported() {
        let mut d = resources();
        w16(&mut d, 0x54e, 2);
        w32(&mut d, 0x558, 0x411);
        w32(&mut d, 0x55c, 0x60);
        assert_eq!(parse_pe_extras(&d).unwrap().resources.len(), 2);
    }
    #[test]
    fn resource_aliased_walk_has_global_step_budget() {
        let mut d = resources();
        dd(&mut d, 2, 0x500, 0x5000);
        w16(&mut d, 0x50e, 512);
        w16(&mut d, 0x250e, 512);
        w16(&mut d, 0x450e, 0);
        for i in 0..512 {
            w32(&mut d, 0x510 + i * 8, 24);
            w32(&mut d, 0x514 + i * 8, 0x80002000);
            w32(&mut d, 0x2510 + i * 8, 7);
            w32(&mut d, 0x2514 + i * 8, 0x80004000);
        }
        assert!(parse_pe_extras(&d)
            .unwrap_err()
            .contains("iteration budget"));
    }
    #[test]
    fn resource_aliased_walk_has_global_output_budget() {
        let mut d = resources();
        w16(&mut d, 0x50e, 2);
        w32(&mut d, 0x518, 24);
        w32(&mut d, 0x51c, 0x80000020);
        dd(&mut d, 2, 0x500, 0x2000);
        w16(&mut d, 0x54e, 512);
        for i in 0..512 {
            w32(&mut d, 0x550 + i * 8, 0x409);
            w32(&mut d, 0x554 + i * 8, 0x1800);
        }
        w32(&mut d, 0x1d00, rva(0x900));
        w32(&mut d, 0x1d04, 16);
        assert!(parse_pe_extras(&d)
            .unwrap_err()
            .contains("resource output budget"));
    }
    #[test]
    fn valid_export_has_named_va_schema() {
        let e = parse_pe_exports(&exports()).unwrap();
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].name, "Export");
        assert_eq!(e[0].address, 0x140000000 + rva(0x1000) as u64);
    }
    #[test]
    fn export_count_is_checked_before_table_allocation() {
        let mut d = exports();
        w32(&mut d, 0x518, u32::MAX);
        assert!(parse_pe_exports(&d).unwrap_err().contains("budget"));
    }
    #[test]
    fn export_name_must_be_backed() {
        let mut d = exports();
        w32(&mut d, 0x720, 0x25000);
        assert!(parse_pe_exports(&d).is_err());
    }
    #[test]
    fn export_ordinal_must_index_address_array() {
        let mut d = exports();
        w16(&mut d, 0x740, 1);
        assert!(parse_pe_exports(&d).is_err());
    }
    #[test]
    fn export_forwarders_keep_existing_exclusion() {
        let mut d = exports();
        w32(&mut d, 0x700, rva(0x580));
        d[0x580..0x58d].copy_from_slice(b"DLL.Function\0");
        assert!(parse_pe_exports(&d).unwrap().is_empty());
    }
    #[test]
    fn scan_budget_charges_repeated_aliases() {
        let mut b = Budget::new();
        let mut name = vec![b'x'; 4097];
        name[4096] = 0;
        while b.scan >= name.len() {
            b.name(&name).unwrap();
        }
        assert!(b.name(&name).unwrap_err().contains("name scan budget"));
    }
    #[test]
    fn iteration_budget_is_exact() {
        let mut b = Budget::new();
        for _ in 0..MAX_PE_STEPS {
            b.step().unwrap();
        }
        assert!(b.step().unwrap_err().contains("iteration budget"));
    }
    #[test]
    fn input_cap_is_checked_before_header_parse() {
        let mut d = vec![0; MAX_PE_INPUT_BYTES + 1];
        d[..2].copy_from_slice(b"MZ");
        assert!(parse_pe_imports(&d).unwrap_err().contains("input budget"));
    }
    #[test]
    fn bounded_mutations_do_not_panic() {
        let base = fixture(1, 1, 4, 4);
        let mut seed = 0x123456789u64;
        for _ in 0..512 {
            let mut d = base.clone();
            for _ in 0..8 {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                let p = (seed as usize) % d.len();
                d[p] = (seed >> 32) as u8;
            }
            let _ = parse_pe_imports(&d);
            let _ = parse_pe_exports(&d);
            let _ = parse_pe_extras(&d);
        }
    }
}

#[cfg(test)]
mod additional_regressions {
    use super::hardening_import_tests::fixture;
    use super::*;
    fn w16(d: &mut [u8], p: usize, v: u16) {
        d[p..p + 2].copy_from_slice(&v.to_le_bytes());
    }
    fn w32(d: &mut [u8], p: usize, v: u32) {
        d[p..p + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn w64(d: &mut [u8], p: usize, v: u64) {
        d[p..p + 8].copy_from_slice(&v.to_le_bytes());
    }
    fn rva(p: usize) -> u32 {
        (p + 0x1e00) as u32
    }
    #[test]
    fn pe32_named_and_ordinal_imports_keep_schema() {
        let mut d = fixture(1, 1, 4, 4);
        w16(&mut d, 0x84, 0x14c);
        w16(&mut d, 0x98, 0x10b);
        w32(&mut d, 0x98 + 28, 0x400000);
        w32(&mut d, 0x98 + 92, 16);
        w32(&mut d, 0x98 + 104, rva(0x200));
        w32(&mut d, 0x98 + 108, 40);
        w32(&mut d, 0x2000, rva(0x1c000));
        w32(&mut d, 0x2004, 0x80000007);
        w32(&mut d, 0x2008, 0);
        let i = parse_pe_imports(&d).unwrap();
        assert_eq!(i.len(), 2);
        assert_eq!(i[0].name.as_deref(), Some("NNNN"));
        assert_eq!(i[1].ordinal, Some(7));
        assert_eq!(i[1].thunk_va, 0x403e04);
    }
    #[test]
    fn original_first_thunk_zero_uses_first_thunk() {
        let mut d = fixture(1, 1, 4, 4);
        w32(&mut d, 0x200, 0);
        assert_eq!(parse_pe_imports(&d).unwrap().len(), 1);
    }
    #[test]
    fn import_thunk_va_overflow_is_error() {
        let mut d = fixture(1, 1, 4, 4);
        w64(&mut d, 0xb0, u64::MAX - 1);
        assert!(parse_pe_imports(&d).is_err());
    }
    #[test]
    fn reserved_ordinal_bits_are_not_valid_ordinal_evidence() {
        let mut d = fixture(1, 1, 0, 4);
        w64(&mut d, 0x2000, 0x8000000000010007);
        assert!(parse_pe_imports(&d).is_err());
    }
    #[test]
    fn zero_dll_rva_is_not_a_header_name() {
        let mut d = fixture(1, 1, 4, 4);
        w32(&mut d, 0x20c, 0);
        assert!(parse_pe_imports(&d).is_err());
    }
    #[test]
    fn named_import_cannot_continue_into_adjacent_raw_section() {
        let mut d = fixture(1, 1, 4, 4);
        w16(&mut d, 0x86, 2);
        w32(&mut d, 0x188 + 8, 0x200);
        w32(&mut d, 0x188 + 16, 0x200);
        w32(&mut d, 0x1b0 + 8, 0x200);
        w32(&mut d, 0x1b0 + 12, 0x30000);
        w32(&mut d, 0x1b0 + 16, 0x200);
        w32(&mut d, 0x1b0 + 20, 0x400);
        w32(&mut d, 0x200, rva(0x280));
        w32(&mut d, 0x210, rva(0x280));
        w32(&mut d, 0x20c, rva(0x270));
        d[0x270..0x274].copy_from_slice(b"DLL\0");
        w64(&mut d, 0x280, rva(0x3fa) as u64);
        d[0x3fc..0x404].copy_from_slice(b"CROSSED\0");
        assert!(parse_pe_imports(&d).is_err());
    }
}
