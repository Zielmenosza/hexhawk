use super::pe_imports::parse_pe_section_names;
use capstone::arch::{self, x86::X86OperandType, ArchOperand};
use capstone::{prelude::*, Insn};
use memmap2::MmapOptions;
use object::{Architecture, File as ObjectFile, Object, ObjectSection};
use serde::Serialize;
use std::collections::{BTreeSet, HashMap};
use std::fs;

#[derive(Debug, Clone, Serialize)]
pub struct CfgNode {
    pub id: String,
    pub label: Option<String>,
    pub start: Option<u64>,
    pub end: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instruction_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_type: Option<String>, // "entry", "fallthrough", "target", "external"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub layout_x: Option<i32>, // For hierarchical layout
    #[serde(skip_serializing_if = "Option::is_none")]
    pub layout_y: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub layout_depth: Option<i32>, // Depth in block hierarchy
}

#[derive(Debug, Clone, Serialize)]
pub struct CfgEdge {
    pub source: String,
    pub target: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>, // "branch", "fallthrough", "call"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub condition: Option<String>, // "conditional", "unconditional"
}

#[derive(Debug, Clone, Serialize)]
pub struct CfgGraph {
    pub nodes: Vec<CfgNode>,
    pub edges: Vec<CfgEdge>,
    pub truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_budget: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub edge_budget: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub omitted_nodes: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub omitted_edges: Option<usize>,
}

const MAX_CFG_NODES: usize = 2_000;
const MAX_CFG_EDGES: usize = 4_000;
const MAX_CFG_BYTES: usize = 256 * 1024;
const MAX_CFG_INSTRUCTIONS: usize = 8_192;
const MAX_MAPPED_FILE_BYTES: u64 = 256 * 1024 * 1024;

fn finish_cfg_graph(mut nodes: Vec<CfgNode>, mut edges: Vec<CfgEdge>) -> CfgGraph {
    let original_node_count = nodes.len();
    let original_edge_count = edges.len();

    if nodes.len() > MAX_CFG_NODES {
        nodes.truncate(MAX_CFG_NODES);
        let kept_ids: std::collections::HashSet<String> =
            nodes.iter().map(|node| node.id.clone()).collect();
        edges.retain(|edge| kept_ids.contains(&edge.source) && kept_ids.contains(&edge.target));
    }

    if edges.len() > MAX_CFG_EDGES {
        edges.truncate(MAX_CFG_EDGES);
    }

    let omitted_nodes = original_node_count.saturating_sub(nodes.len());
    let omitted_edges = original_edge_count.saturating_sub(edges.len());
    let truncated = omitted_nodes > 0 || omitted_edges > 0;

    CfgGraph {
        nodes,
        edges,
        truncated,
        node_budget: truncated.then_some(MAX_CFG_NODES),
        edge_budget: truncated.then_some(MAX_CFG_EDGES),
        omitted_nodes: truncated.then_some(omitted_nodes),
        omitted_edges: truncated.then_some(omitted_edges),
    }
}

// Reject malformed raw section extents; never expand the requested byte budget.
fn snap_to_text_section(
    data: &[u8],
    offset: usize,
    length: usize,
    pe_section_names: &[String],
) -> Result<(usize, usize), String> {
    if offset != 0 {
        return Ok((offset, length));
    }
    let Ok(obj) = ObjectFile::parse(data) else {
        return Ok((offset, length));
    };
    let is_pe = obj.format() == object::BinaryFormat::Pe;
    if is_pe && obj.sections().count() != pe_section_names.len() {
        return Err("PE section name count mismatch".into());
    }
    let sec = obj.sections().enumerate().find(|(index, s)| {
        let name = if is_pe {
            pe_section_names[*index].as_str()
        } else {
            s.name().unwrap_or("")
        };
        name.eq_ignore_ascii_case(".text") || name.eq_ignore_ascii_case(".code") || name.eq_ignore_ascii_case("__text")
    });
    let Some((_, sec)) = sec else {
        return Ok((offset, length));
    };
    // object 0.31 reports min(VirtualSize, SizeOfRawData) for PE. Validate
    // the declared raw extent too, so a small virtual size cannot hide bad bounds.
    let raw_header = if obj.format() == object::BinaryFormat::Pe {
        let sections = if obj.is_64() {
            object::read::pe::PeFile64::parse(data)
                .map_err(|_| "Invalid PE64 header")?
                .section_table()
        } else {
            object::read::pe::PeFile32::parse(data)
                .map_err(|_| "Invalid PE32 header")?
                .section_table()
        };
        Some(
            sections
                .section(sec.index().0)
                .map_err(|_| "Invalid PE text section index")?,
        )
    } else {
        None
    };
    if let Some(header) = raw_header {
        let raw_start = u64::from(header.pointer_to_raw_data.get(object::LittleEndian));
        let raw_size = u64::from(header.size_of_raw_data.get(object::LittleEndian));
        let raw_end = raw_start
            .checked_add(raw_size)
            .ok_or("PE text section range overflow")?;
        if raw_end > u64::try_from(data.len()).map_err(|_| "File size cannot be represented")? {
            return Err("PE text section raw range extends beyond EOF".into());
        }
    }
    let Some((file_offset, file_size)) = sec.file_range() else {
        return Ok((offset, length));
    };
    let start =
        usize::try_from(file_offset).map_err(|_| "Text section offset cannot be represented")?;
    let size = usize::try_from(file_size).map_err(|_| "Text section size cannot be represented")?;
    let section_end = start
        .checked_add(size)
        .ok_or("Text section range overflow")?;
    if section_end > data.len() {
        return Err("Text section range extends beyond EOF".into());
    }
    Ok((start, size.min(length)))
}

fn is_unconditional_jump(mnemonic: &str) -> bool {
    matches!(mnemonic, "jmp" | "jmpq")
}

fn is_conditional_jump(mnemonic: &str) -> bool {
    (mnemonic.starts_with('j') && !matches!(mnemonic, "jmp" | "jmpq" | "jecxz" | "jrcxz"))
        || mnemonic.starts_with("loop")
}

fn is_call(mnemonic: &str) -> bool {
    matches!(mnemonic, "call" | "callq")
}

fn is_return(mnemonic: &str) -> bool {
    mnemonic.starts_with("ret")
}

fn is_system_call(mnemonic: &str) -> bool {
    matches!(mnemonic, "syscall" | "sysenter" | "int")
}

fn x86_target_address(cs: &Capstone, ins: &Insn) -> Option<u64> {
    cs.insn_detail(ins).ok().and_then(|detail| {
        detail
            .arch_detail()
            .operands()
            .into_iter()
            .find_map(|operand| match operand {
                ArchOperand::X86Operand(op) => match op.op_type {
                    X86OperandType::Imm(imm) => Some(imm as u64),
                    _ => None,
                },
                _ => None,
            })
    })
}

pub(super) fn validate_cfg_request(offset: usize, length: usize) -> Result<(), String> {
    offset.checked_add(length).ok_or("CFG range overflow")?;
    if length > MAX_CFG_BYTES {
        return Err(format!(
            "CFG byte budget exceeded (maximum {MAX_CFG_BYTES})"
        ));
    }
    Ok(())
}

// Legacy Rust/CLI entry point. Native IPC uses analysis_bound's checked snapshot.
pub fn build_cfg(path: String, offset: usize, length: usize) -> Result<CfgGraph, String> {
    validate_cfg_request(offset, length)?;
    // Bound object parsing and the mapping before decoder allocations.
    let file_handle = fs::File::open(&path).map_err(|e| format!("Failed to open file: {e}"))?;
    let file_len = file_handle
        .metadata()
        .map_err(|e| format!("Failed to stat file: {e}"))?
        .len();
    if file_len > MAX_MAPPED_FILE_BYTES {
        return Err(format!(
            "CFG file budget exceeded (maximum {MAX_MAPPED_FILE_BYTES} bytes)"
        ));
    }
    let mmap = unsafe {
        MmapOptions::new()
            .len(usize::try_from(file_len).map_err(|_| "File size cannot be represented")?)
            .map(&file_handle)
            .map_err(|e| format!("Failed to mmap file: {e}"))?
    };
    cfg_snapshot(&mmap, offset, length)
}

pub(super) fn cfg_snapshot(data: &[u8], offset: usize, length: usize) -> Result<CfgGraph, String> {
    validate_cfg_request(offset, length)?;
    let pe_section_names = parse_pe_section_names(data)?;

    if offset >= data.len() {
        return Ok(finish_cfg_graph(vec![], vec![]));
    }

    let (effective_offset, effective_length) = snap_to_text_section(data, offset, length, &pe_section_names)?;
    let end = effective_offset
        .checked_add(effective_length)
        .ok_or("Snapped CFG range overflow")?
        .min(data.len());
    let slice = &data[effective_offset..end];
    let base_addr =
        u64::try_from(effective_offset).map_err(|_| "CFG offset cannot be represented")?;
    let end_addr = u64::try_from(end).map_err(|_| "CFG end cannot be represented")?;

    // Auto-detect architecture; fall back to x86-64
    let detected_arch = ObjectFile::parse(data)
        .map(|f| f.architecture())
        .unwrap_or(Architecture::X86_64);

    let cs = match detected_arch {
        Architecture::I386 => Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode32)
            .detail(true)
            .build(),
        Architecture::Arm => Capstone::new()
            .arm()
            .mode(arch::arm::ArchMode::Arm)
            .detail(true)
            .build(),
        Architecture::Aarch64 => Capstone::new()
            .arm64()
            .mode(arch::arm64::ArchMode::Arm)
            .detail(true)
            .build(),
        // Default: x86-64 (covers X86_64 and any unsupported arch as fallback)
        _ => Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode64)
            .detail(true)
            .build(),
    }
    .map_err(|e| format!("Failed to initialize Capstone: {e}"))?;

    let instructions = cs
        // One bounded sentinel instruction proves an over-budget request.
        .disasm_count(slice, base_addr, MAX_CFG_INSTRUCTIONS + 1)
        .map_err(|e| format!("Failed to disassemble for CFG: {}", e))?;

    if instructions.len() > MAX_CFG_INSTRUCTIONS {
        return Err(format!("CFG instruction budget exceeded (maximum {MAX_CFG_INSTRUCTIONS}); request a smaller range"));
    }
    let decoded_bytes = instructions.iter().try_fold(0usize, |total, ins| {
        total
            .checked_add(ins.bytes().len())
            .ok_or("CFG decoded byte count overflow")
    })?;
    if decoded_bytes != slice.len() {
        return Err("CFG range contains undecoded bytes; complete coverage is unavailable".into());
    }

    if instructions.is_empty() {
        return Ok(finish_cfg_graph(vec![], vec![]));
    }

    #[derive(Debug, Clone)]
    struct InstructionInfo {
        address: u64,
        size: u64,
        #[allow(dead_code)]
        mnemonic: String,
        target: Option<u64>,
        is_uncond_jump: bool,
        is_cond_jump: bool,
        is_call: bool,
        is_return: bool,
        is_syscall: bool,
    }

    let mut ins_info: Vec<InstructionInfo> = Vec::new();
    let mut block_starts = BTreeSet::new();
    let mut address_to_index = HashMap::new();

    // Block 0: Entry point
    block_starts.insert(base_addr);

    // Pass 1: Disassemble and identify block boundaries
    for (idx, ins) in instructions.iter().enumerate() {
        let address = ins.address();
        let size = u64::try_from(ins.bytes().len())
            .map_err(|_| "CFG instruction size cannot be represented")?;
        let next_address = address
            .checked_add(size)
            .ok_or("CFG instruction range overflow")?;
        let mnemonic = ins.mnemonic().unwrap_or("").to_lowercase();
        let target = x86_target_address(&cs, ins);
        let is_uncond = is_unconditional_jump(&mnemonic);
        let is_cond = is_conditional_jump(&mnemonic);
        let is_call_inst = is_call(&mnemonic);
        let is_ret = is_return(&mnemonic);
        let is_sys = is_system_call(&mnemonic);

        // Add jump targets as block starts
        if let Some(target_addr) = target {
            if target_addr >= base_addr && target_addr < end_addr {
                block_starts.insert(target_addr);
            }
        }

        // Add fallthrough points as block starts
        if is_cond {
            // Conditional jump: next instruction is a fallthrough target
            if next_address < end_addr {
                block_starts.insert(next_address);
            }
        } else if is_uncond || is_ret || is_sys {
            // Unconditional jump or return: next instruction starts a new block
            if next_address < end_addr {
                block_starts.insert(next_address);
            }
        }

        // For calls, the next instruction is also a fallthrough
        if is_call_inst && next_address < end_addr {
            block_starts.insert(next_address);
        }

        // Stop before building nodes/edges or laying out an over-budget graph.
        if block_starts.len() > MAX_CFG_NODES {
            return Err(format!(
                "CFG node budget exceeded (maximum {MAX_CFG_NODES}); request a smaller range"
            ));
        }

        address_to_index.insert(address, idx);

        ins_info.push(InstructionInfo {
            address,
            size,
            mnemonic,
            target,
            is_uncond_jump: is_uncond,
            is_cond_jump: is_cond,
            is_call: is_call_inst,
            is_return: is_ret,
            is_syscall: is_sys,
        });
    }

    // Pass 2: Create blocks from identified block starts
    let block_starts_vec: Vec<u64> = block_starts.into_iter().collect();
    let mut nodes = Vec::new();
    let mut block_id_by_start = HashMap::new();

    for (index, &start) in block_starts_vec.iter().enumerate() {
        let id = format!("block_{}", index);
        block_id_by_start.insert(start, id.clone());

        let block_type = if start == base_addr {
            "entry".to_string()
        } else {
            "target".to_string()
        };

        nodes.push(CfgNode {
            id,
            label: Some(format!("0x{:x}", start)),
            start: Some(start),
            end: None,
            instruction_count: None,
            block_type: Some(block_type),
            layout_x: None,
            layout_y: None,
            layout_depth: None,
        });
    }

    // Pass 3: Compute block boundaries and edges
    let mut edges = Vec::new();
    let mut external_nodes = HashMap::new();
    let mut external_counter = 0;

    for (idx, &start) in block_starts_vec.iter().enumerate() {
        let end_address = block_starts_vec.get(idx + 1).cloned().unwrap_or(end_addr);
        let block_id = block_id_by_start.get(&start).unwrap().clone();

        if let Some(&instr_index) = address_to_index.get(&start) {
            let block_instructions: Vec<&InstructionInfo> = ins_info
                .iter()
                .skip(instr_index)
                .take_while(|ins| ins.address < end_address)
                .collect();

            if block_instructions.is_empty() {
                continue;
            }

            // Compute block end (address of last instruction's last byte)
            let last = block_instructions
                .last()
                .expect("nonempty block checked above");
            let block_end = last
                .address
                .checked_add(last.size)
                .and_then(|end| end.checked_sub(1))
                .ok_or("CFG block range overflow")?;

            let instr_count = block_instructions.len();

            // Update node with computed boundaries
            if let Some(node) = nodes.iter_mut().find(|node| node.start == Some(start)) {
                node.end = Some(block_end);
                node.instruction_count = Some(instr_count);
                node.label = Some(format!("0x{:x}\n({} i)", start, instr_count));
            }

            // Analyze last instruction in block to determine outgoing edges
            if let Some(last_ins) = block_instructions.last() {
                // Jump target (if exists)
                if let Some(target_addr) = last_ins.target {
                    let target_id = if let Some(id) = block_id_by_start.get(&target_addr) {
                        id.clone()
                    } else {
                        // External target
                        if !external_nodes.contains_key(&target_addr)
                            && nodes.len() + external_nodes.len() >= MAX_CFG_NODES
                        {
                            return Err(format!("CFG node budget exceeded (maximum {MAX_CFG_NODES}); request a smaller range"));
                        }
                        let entry = external_nodes.entry(target_addr).or_insert_with(|| {
                            let id = format!("external_{}", external_counter);
                            external_counter += 1;
                            id
                        });
                        entry.clone()
                    };

                    let condition = if last_ins.is_cond_jump {
                        "conditional".to_string()
                    } else {
                        "unconditional".to_string()
                    };

                    edges.push(CfgEdge {
                        source: block_id.clone(),
                        target: target_id,
                        kind: Some("branch".to_string()),
                        condition: Some(condition),
                    });
                }

                // Fallthrough edges
                let next_block_start = block_starts_vec.get(idx + 1).cloned();

                if last_ins.is_cond_jump {
                    // Conditional jumps have fallthrough
                    if let Some(next_start) = next_block_start {
                        if let Some(next_id) = block_id_by_start.get(&next_start) {
                            edges.push(CfgEdge {
                                source: block_id.clone(),
                                target: next_id.clone(),
                                kind: Some("fallthrough".to_string()),
                                condition: Some("conditional".to_string()),
                            });
                        }
                    }
                } else if last_ins.is_call {
                    // Calls fall through to next block
                    if let Some(next_start) = next_block_start {
                        if let Some(next_id) = block_id_by_start.get(&next_start) {
                            edges.push(CfgEdge {
                                source: block_id.clone(),
                                target: next_id.clone(),
                                kind: Some("fallthrough".to_string()),
                                condition: None,
                            });
                        }
                    }
                } else if !last_ins.is_uncond_jump && !last_ins.is_return && !last_ins.is_syscall {
                    // Regular instructions fall through
                    if let Some(next_start) = next_block_start {
                        if let Some(next_id) = block_id_by_start.get(&next_start) {
                            edges.push(CfgEdge {
                                source: block_id.clone(),
                                target: next_id.clone(),
                                kind: Some("fallthrough".to_string()),
                                condition: None,
                            });
                        }
                    }
                }
            }
        }
    }

    if edges.len() > MAX_CFG_EDGES {
        return Err(format!(
            "CFG edge budget exceeded (maximum {MAX_CFG_EDGES}); request a smaller range"
        ));
    }

    // Pass 4: Add external target nodes (already admitted by the node budget)
    for (target_addr, id) in external_nodes {
        nodes.push(CfgNode {
            id,
            label: Some(format!("external 0x{:x}", target_addr)),
            start: Some(target_addr),
            end: None,
            instruction_count: None,
            block_type: Some("external".to_string()),
            layout_x: None,
            layout_y: None,
            layout_depth: None,
        });
    }

    // Pass 5: Compute hierarchical layout
    let mut depth_map: HashMap<String, i32> = HashMap::new();
    let mut position_map: HashMap<String, i32> = HashMap::new();

    // BFS to compute depths — must track visited nodes to avoid infinite loops
    // on cyclic CFGs (back-edges from loops/branches in real code).
    let mut queue = std::collections::VecDeque::new();
    let mut visited: std::collections::HashSet<String> = std::collections::HashSet::new();
    queue.push_back("block_0".to_string());
    depth_map.insert("block_0".to_string(), 0);

    while let Some(node_id) = queue.pop_front() {
        if !visited.insert(node_id.clone()) {
            continue; // Already processed — skip to prevent infinite cycles
        }
        let current_depth = *depth_map.get(&node_id).unwrap_or(&0);

        // Find all edges from this node
        for edge in &edges {
            if edge.source == node_id {
                let next_depth = current_depth + 1;
                let entry = depth_map.entry(edge.target.clone()).or_insert(next_depth);
                *entry = (*entry).min(next_depth);

                if !visited.contains(&edge.target) {
                    queue.push_back(edge.target.clone());
                }
            }
        }
    }

    // Group nodes by depth and assign x positions
    let mut depth_groups: HashMap<i32, Vec<String>> = HashMap::new();
    for (node_id, depth) in &depth_map {
        depth_groups
            .entry(*depth)
            .or_insert_with(Vec::new)
            .push(node_id.clone());
    }

    for (_depth, node_ids) in depth_groups {
        for (idx, node_id) in node_ids.iter().enumerate() {
            position_map.insert(node_id.clone(), idx as i32 * 300);
        }
    }

    // Apply layout to nodes
    for node in &mut nodes {
        if let Some(depth) = depth_map.get(&node.id) {
            node.layout_depth = Some(*depth);
            node.layout_y = Some(*depth * 180);
        }
        if let Some(x) = position_map.get(&node.id) {
            node.layout_x = Some(*x);
        }
    }

    Ok(finish_cfg_graph(nodes, edges))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn range_fixture(name: &str, data: &[u8]) -> String {
        let path = std::env::var_os("TMPDIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(std::env::temp_dir)
            .join(format!("range-cfg-{name}-{}.bin", std::process::id()));
        fs::write(&path, data).expect("write inert fixture");
        path.to_string_lossy().into_owned()
    }

    #[test]
    fn range_cfg_rejects_byte_budget_before_decode() {
        let path = range_fixture("bytes", &[0x90]);
        let result = build_cfg(path.clone(), 0, 256 * 1024 + 1);
        let _ = fs::remove_file(path);
        assert!(result.is_err());
    }

    #[test]
    fn range_cfg_rejects_offset_overflow() {
        let path = range_fixture("overflow", &[0x90, 0x90]);
        let result = build_cfg(path.clone(), 1, usize::MAX);
        let _ = fs::remove_file(path);
        assert!(result.is_err());
    }

    #[test]
    fn range_cfg_snap_respects_requested_length() {
        let path = range_fixture(
            "snap-length",
            &minimal_elf64_x86_64_text_at_nonzero_offset(),
        );
        let result = build_cfg(path.clone(), 0, 1);
        let _ = fs::remove_file(path);
        let result = result.expect("bounded cfg");
        assert_eq!(result.nodes[0].end, Some(0x100));
        assert_eq!(result.nodes[0].instruction_count, Some(1));
    }

    #[test]
    fn range_cfg_rejects_snapped_section_beyond_eof() {
        let mut data = minimal_elf64_x86_64_text_at_nonzero_offset();
        put_u64(&mut data, 0x128 + 64 + 0x18, 0x1000);
        let path = range_fixture("snap-eof", &data);
        let result = build_cfg(path.clone(), 0, 1);
        let _ = fs::remove_file(path);
        assert!(result.is_err());
    }

    #[test]
    fn range_cfg_rejects_instruction_budget_before_graph_computation() {
        let path = range_fixture("instructions", &vec![0x90; 8193]);
        let result = build_cfg(path.clone(), 0, 8193);
        let _ = fs::remove_file(path);
        assert!(result.is_err());
    }

    #[test]
    fn range_cfg_rejects_node_budget_before_layout() {
        let path = range_fixture("nodes", &vec![0xC3; 2001]);
        let result = build_cfg(path.clone(), 0, 2001);
        let _ = fs::remove_file(path);
        assert!(
            result.is_err(),
            "response truncation is not a computation bound"
        );
    }

    #[test]
    fn range_cfg_rejects_undecoded_tail_instead_of_full_coverage() {
        let path = range_fixture("invalid", &[0x90, 0x0F]);
        let result = build_cfg(path.clone(), 0, 2);
        let _ = fs::remove_file(path);
        assert!(result.is_err());
    }

    #[test]
    fn range_cfg_pe64_snap_is_bounded_and_zero_length_is_empty() {
        let path = range_fixture("pe64", &range_pe64_text());
        let result = build_cfg(path.clone(), 0, 1).unwrap();
        assert_eq!(result.nodes.len(), 1);
        assert_eq!(result.nodes[0].start, Some(0x200));
        assert_eq!(result.nodes[0].end, Some(0x200));
        assert!(!result.truncated);
        let empty = build_cfg(path.clone(), 0, 0).unwrap();
        let _ = fs::remove_file(path);
        assert!(empty.nodes.is_empty());
    }

    #[test]
    fn range_cfg_pe64_rejects_raw_section_extent_beyond_eof() {
        let mut data = range_pe64_text();
        put_u32(&mut data, 0x19C, 0x1000);
        let path = range_fixture("pe64-eof", &data);
        let result = build_cfg(path.clone(), 0, 1);
        let _ = fs::remove_file(path);
        assert!(result.unwrap_err().contains("beyond EOF"));
    }

    #[test]
    fn range_cfg_accepts_exact_instruction_and_node_budgets() {
        let path = range_fixture("exact-instructions", &vec![0x90; 8192]);
        let result = build_cfg(path.clone(), 0, 8192).unwrap();
        let _ = fs::remove_file(path);
        assert_eq!(result.nodes[0].instruction_count, Some(8192));
        assert!(!result.truncated);
        let path = range_fixture("exact-nodes", &vec![0xC3; 2000]);
        let result = build_cfg(path.clone(), 0, 2000).unwrap();
        let _ = fs::remove_file(path);
        assert_eq!(result.nodes.len(), 2000);
        assert!(!result.truncated);
    }

    #[test]
    fn range_cfg_external_nodes_are_included_in_computation_budget() {
        let data = [0xE8, 0xFF, 0xFF, 0xFF, 0x7F].repeat(1001);
        let path = range_fixture("external-nodes", &data);
        let result = build_cfg(path.clone(), 0, data.len());
        let _ = fs::remove_file(path);
        assert!(result.unwrap_err().contains("node budget"));
    }

    fn range_pe64_text() -> Vec<u8> {
        let mut data = vec![0u8; 0x220];
        data[0..2].copy_from_slice(b"MZ");
        put_u32(&mut data, 0x3C, 0x80);
        data[0x80..0x84].copy_from_slice(b"PE\0\0");
        put_u16(&mut data, 0x84, 0x8664);
        put_u16(&mut data, 0x86, 1);
        put_u16(&mut data, 0x94, 0xF0);
        put_u16(&mut data, 0x96, 0x22);
        put_u16(&mut data, 0x98, 0x20B);
        put_u32(&mut data, 0xA8, 0x1000);
        put_u64(&mut data, 0xB0, 0x140000000);
        put_u32(&mut data, 0xB8, 0x1000);
        put_u32(&mut data, 0xBC, 0x200);
        put_u32(&mut data, 0xD0, 0x2000);
        put_u32(&mut data, 0xD4, 0x200);
        put_u32(&mut data, 0x104, 16);
        data[0x188..0x190].copy_from_slice(b".text\0\0\0");
        put_u32(&mut data, 0x190, 7);
        put_u32(&mut data, 0x194, 0x1000);
        put_u32(&mut data, 0x198, 7);
        put_u32(&mut data, 0x19C, 0x200);
        put_u32(&mut data, 0x1AC, 0x60000020);
        data[0x200..0x207].copy_from_slice(&[0x90, 0xB8, 1, 0, 0, 0, 0xC3]);
        assert_eq!(
            ObjectFile::parse(data.as_slice())
                .expect("valid PE64")
                .architecture(),
            Architecture::X86_64
        );
        data
    }

    fn put_u16(buf: &mut [u8], offset: usize, value: u16) {
        buf[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }
    fn put_u32(buf: &mut [u8], offset: usize, value: u32) {
        buf[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn put_u64(buf: &mut [u8], offset: usize, value: u64) {
        buf[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn minimal_elf64_x86_64_text_at_nonzero_offset() -> Vec<u8> {
        let mut data = vec![0u8; 0x248];
        data[0..4].copy_from_slice(b"\x7FELF");
        data[4] = 2; // ELFCLASS64
        data[5] = 1; // little endian
        data[6] = 1; // version
        put_u16(&mut data, 0x10, 2); // ET_EXEC
        put_u16(&mut data, 0x12, 62); // EM_X86_64
        put_u32(&mut data, 0x14, 1);
        put_u64(&mut data, 0x18, 0x400000);
        put_u64(&mut data, 0x28, 0x128); // section header offset
        put_u16(&mut data, 0x34, 64);
        put_u16(&mut data, 0x3A, 64);
        put_u16(&mut data, 0x3C, 3);
        put_u16(&mut data, 0x3E, 2);

        data[0x100..0x107].copy_from_slice(&[0x90, 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3]);
        data[0x108..0x119].copy_from_slice(b"\0.text\0.shstrtab\0");

        let sh_text = 0x128 + 64;
        put_u32(&mut data, sh_text, 1); // name .text
        put_u32(&mut data, sh_text + 4, 1); // SHT_PROGBITS
        put_u64(&mut data, sh_text + 8, 0x6); // alloc + exec
        put_u64(&mut data, sh_text + 0x10, 0x400000);
        put_u64(&mut data, sh_text + 0x18, 0x100);
        put_u64(&mut data, sh_text + 0x20, 7);
        put_u64(&mut data, sh_text + 0x30, 16);

        let sh_names = 0x128 + 128;
        put_u32(&mut data, sh_names, 7); // name .shstrtab
        put_u32(&mut data, sh_names + 4, 3); // SHT_STRTAB
        put_u64(&mut data, sh_names + 0x18, 0x108);
        put_u64(&mut data, sh_names + 0x20, 0x11);
        data
    }

    #[test]
    fn cfg_node_addresses_match_disassembly_after_text_section_snap() {
        let path = std::env::temp_dir().join("hexhawk-cfg-snap-address-basis.elf");
        fs::write(&path, minimal_elf64_x86_64_text_at_nonzero_offset()).expect("write elf");
        let path_string = path.to_string_lossy().to_string();
        let cfg = build_cfg(path_string, 0, 0x200).expect("cfg");
        let _ = fs::remove_file(path);

        let instruction_addresses: std::collections::BTreeSet<u64> =
            [0x100, 0x101, 0x106].into_iter().collect();
        assert!(instruction_addresses.contains(&0x100));
        let mismatched: Vec<u64> = cfg
            .nodes
            .iter()
            .filter(|node| node.block_type.as_deref() != Some("external"))
            .filter_map(|node| node.start)
            .filter(|start| !instruction_addresses.contains(start))
            .collect();
        assert!(
            mismatched.is_empty(),
            "CFG node addresses must use the same snapped text-section basis as disassembly; cfg={:?}, disassembly={:?}",
            mismatched,
            instruction_addresses
        );
    }

    #[test]
    fn cfg_finish_enforces_renderer_budgets_and_reports_omissions() {
        let nodes: Vec<CfgNode> = (0..(MAX_CFG_NODES + 25))
            .map(|idx| CfgNode {
                id: format!("block_{idx}"),
                label: None,
                start: Some(idx as u64),
                end: None,
                instruction_count: None,
                block_type: Some("target".to_string()),
                layout_x: None,
                layout_y: None,
                layout_depth: None,
            })
            .collect();
        let edges: Vec<CfgEdge> = (0..(MAX_CFG_EDGES + 200))
            .map(|idx| CfgEdge {
                source: format!("block_{}", idx % MAX_CFG_NODES),
                target: format!("block_{}", (idx + 1) % MAX_CFG_NODES),
                kind: Some("branch".to_string()),
                condition: None,
            })
            .collect();

        let graph = finish_cfg_graph(nodes, edges);

        assert!(graph.truncated);
        assert_eq!(graph.nodes.len(), MAX_CFG_NODES);
        assert_eq!(graph.edges.len(), MAX_CFG_EDGES);
        assert_eq!(graph.node_budget, Some(MAX_CFG_NODES));
        assert_eq!(graph.edge_budget, Some(MAX_CFG_EDGES));
        assert_eq!(graph.omitted_nodes, Some(25));
        assert_eq!(graph.omitted_edges, Some(200));
    }
}
