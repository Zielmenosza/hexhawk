use capstone::{Insn, prelude::*};
use capstone::arch::{self, ArchOperand, x86::X86OperandType};
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
    pub block_type: Option<String>,  // "entry", "fallthrough", "target", "external"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub layout_x: Option<i32>,  // For hierarchical layout
    #[serde(skip_serializing_if = "Option::is_none")]
    pub layout_y: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub layout_depth: Option<i32>,  // Depth in block hierarchy
}

#[derive(Debug, Clone, Serialize)]
pub struct CfgEdge {
    pub source: String,
    pub target: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,  // "branch", "fallthrough", "call"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub condition: Option<String>,  // "conditional", "unconditional"
}

#[derive(Debug, Clone, Serialize)]
pub struct CfgGraph {
    pub nodes: Vec<CfgNode>,
    pub edges: Vec<CfgEdge>,
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
        detail.arch_detail().operands().into_iter().find_map(|operand| match operand {
            ArchOperand::X86Operand(op) => match op.op_type {
                X86OperandType::Imm(imm) => Some(imm as u64),
                _ => None,
            },
            _ => None,
        })
    })
}

#[tauri::command]
pub fn build_cfg(path: String, offset: usize, length: usize) -> Result<CfgGraph, String> {
    let data = fs::read(&path).map_err(|e| format!("Failed to read file: {}", e))?;

    if offset >= data.len() {
        return Ok(CfgGraph {
            nodes: vec![],
            edges: vec![],
        });
    }

    let end = std::cmp::min(offset + length, data.len());
    let slice = &data[offset..end];

    let cs = Capstone::new()
        .x86()
        .mode(arch::x86::ArchMode::Mode64)
        .detail(true)
        .build()
        .map_err(|e| format!("Failed to initialize Capstone: {}", e))?;

    let instructions = cs
        .disasm_all(slice, offset as u64)
        .map_err(|e| format!("Failed to disassemble for CFG: {}", e))?;

    if instructions.is_empty() {
        return Ok(CfgGraph {
            nodes: vec![],
            edges: vec![],
        });
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
    block_starts.insert(offset as u64);

    // Pass 1: Disassemble and identify block boundaries
    for (idx, ins) in instructions.iter().enumerate() {
        let address = ins.address();
        let size = ins.bytes().len() as u64;
        let mnemonic = ins.mnemonic().unwrap_or("").to_lowercase();
        let target = x86_target_address(&cs, ins);
        let is_uncond = is_unconditional_jump(&mnemonic);
        let is_cond = is_conditional_jump(&mnemonic);
        let is_call_inst = is_call(&mnemonic);
        let is_ret = is_return(&mnemonic);
        let is_sys = is_system_call(&mnemonic);

        // Add jump targets as block starts
        if let Some(target_addr) = target {
            if target_addr >= offset as u64 && target_addr < end as u64 {
                block_starts.insert(target_addr);
            }
        }

        // Add fallthrough points as block starts
        if is_cond {
            // Conditional jump: next instruction is a fallthrough target
            let next_address = address + size;
            if next_address < end as u64 {
                block_starts.insert(next_address);
            }
        } else if is_uncond || is_ret || is_sys {
            // Unconditional jump or return: next instruction starts a new block
            let next_address = address + size;
            if next_address < end as u64 {
                block_starts.insert(next_address);
            }
        }

        // For calls, the next instruction is also a fallthrough
        if is_call_inst {
            let next_address = address + size;
            if next_address < end as u64 {
                block_starts.insert(next_address);
            }
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
        
        let block_type = if start == offset as u64 {
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
        let end_address = block_starts_vec
            .get(idx + 1)
            .cloned()
            .unwrap_or(end as u64);
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
            let block_end = block_instructions
                .last()
                .map(|ins| ins.address + ins.size - 1)
                .unwrap_or(start);
            
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

    // Pass 4: Add external target nodes
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
            continue;  // Already processed — skip to prevent infinite cycles
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
        depth_groups.entry(*depth).or_insert_with(Vec::new).push(node_id.clone());
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

    Ok(CfgGraph { nodes, edges })
}
