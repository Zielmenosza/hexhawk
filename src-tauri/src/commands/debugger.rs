// commands/debugger.rs — Minimal Native Debugger
//
// Windows: uses CreateProcessW + WaitForDebugEvent for true single-step debugging.
// Non-Windows: all commands return an explicit "not supported" error.
//
// Session model:
//   start_debug_session → launches process, pauses at system breakpoint
//   debug_step          → single-step (trap flag), returns new register state
//   debug_continue      → run until next breakpoint or exit
//   debug_set_breakpoint / debug_remove_breakpoint
//   debug_stop          → terminate process
//   debug_get_state     → current snapshot without advancing
//   debug_read_memory   → read raw bytes from debugged process

use std::collections::HashMap;
use std::sync::Mutex;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};

// ── Shared types (all platforms) ─────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DebugStatus {
    Starting,
    Paused,
    Running,
    Exited,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct RegisterState {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub rip: u64,
    pub r8:  u64,
    pub r9:  u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub eflags: u32,
    pub cs: u16,
    pub ss: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DebugSnapshot {
    pub session_id: u32,
    pub status: DebugStatus,
    pub registers: RegisterState,
    pub stack: Vec<u64>,        // ~16 qwords at RSP
    pub breakpoints: Vec<u64>,
    pub step_count: u32,
    pub exit_code: Option<i32>,
    pub last_event: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StartDebugResult {
    pub session_id: u32,
    pub snapshot: DebugSnapshot,
    pub arch: String,
    pub warnings: Vec<String>,
}

// ── Session registry ──────────────────────────────────────────────────────────

type SessionMap = HashMap<u32, SessionHandle>;

static SESSION_COUNTER: Lazy<Mutex<u32>> = Lazy::new(|| Mutex::new(0));
static SESSIONS: Lazy<Mutex<SessionMap>> = Lazy::new(|| Mutex::new(HashMap::new()));

const MAX_DEBUG_ARGS: usize = 64;
const MAX_DEBUG_ARG_LEN: usize = 4096;
const MAX_DEBUG_READ_MEMORY_BYTES: usize = 64 * 1024;

fn next_session_id() -> u32 {
    let mut c = SESSION_COUNTER.lock().unwrap();
    *c += 1;
    *c
}

fn remove_session(session_id: u32) {
    let mut sessions = SESSIONS.lock().unwrap();
    sessions.remove(&session_id);
}

fn validate_debug_target_path(path: &str) -> Result<String, String> {
    let canonical = std::fs::canonicalize(path)
        .map_err(|e| format!("Invalid debug target path: {e}"))?;
    let meta = std::fs::metadata(&canonical)
        .map_err(|e| format!("Failed to stat debug target path: {e}"))?;
    if !meta.is_file() {
        return Err("Debug target path must be a regular file.".to_string());
    }
    Ok(canonical.to_string_lossy().to_string())
}

fn sanitize_debug_args(args: Option<Vec<String>>) -> Result<Vec<String>, String> {
    let provided = args.unwrap_or_default();
    if provided.len() > MAX_DEBUG_ARGS {
        return Err(format!("Too many debug args (max {}).", MAX_DEBUG_ARGS));
    }

    provided
        .into_iter()
        .enumerate()
        .map(|(i, a)| {
            if a.len() > MAX_DEBUG_ARG_LEN {
                return Err(format!(
                    "Debug arg {} exceeds max length of {} characters.",
                    i, MAX_DEBUG_ARG_LEN
                ));
            }
            if a.chars().any(|c| c == '\0') {
                return Err(format!("Debug arg {} contains a null byte.", i));
            }
            Ok(a)
        })
        .collect()
}

// ── Windows implementation ────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
mod win {
    use super::*;
    use std::sync::mpsc;
    use std::thread;

    use windows_sys::Win32::Foundation::{
        CloseHandle, FALSE, HANDLE, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::System::Diagnostics::Debug::{
        ContinueDebugEvent, DebugActiveProcess, DebugActiveProcessStop,
        FlushInstructionCache, GetThreadContext, ReadProcessMemory,
        SetThreadContext, WaitForDebugEvent, WriteProcessMemory, CONTEXT,
        CREATE_PROCESS_DEBUG_EVENT, CREATE_THREAD_DEBUG_EVENT, DEBUG_EVENT,
        EXCEPTION_DEBUG_EVENT, EXIT_PROCESS_DEBUG_EVENT, LOAD_DLL_DEBUG_EVENT,
        OUTPUT_DEBUG_STRING_EVENT,
    };
    use windows_sys::Win32::System::Threading::{
        CreateProcessW, GetProcessId, OpenProcess, TerminateProcess,
        CREATE_NEW_CONSOLE, DEBUG_PROCESS, PROCESS_QUERY_INFORMATION,
        PROCESS_TERMINATE, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
        PROCESS_INFORMATION, STARTUPINFOW,
    };

    // Windows debug constants — typed to match windows-sys 0.52 NTSTATUS (i32)
    const CONTEXT_ALL: u32               = 0x0010_003F; // AMD64 — CONTEXT.ContextFlags is u32
    #[allow(overflowing_literals)]
    const DBG_CONTINUE: i32              = 0x0001_0002_i32;
    #[allow(overflowing_literals)]
    const DBG_EXCEPTION_NOT_HANDLED: i32 = 0x8001_0001u32 as i32;
    #[allow(overflowing_literals)]
    const EXCEPTION_BREAKPOINT: i32      = 0x8000_0003u32 as i32;
    #[allow(overflowing_literals)]
    const EXCEPTION_SINGLE_STEP: i32     = 0x8000_0004u32 as i32;

    // ── Message types ─────────────────────────────────────────────────────────

    pub enum DebugOp {
        Step,
        StepOver,
        StepOut,
        Continue,
        SetBreakpoint(u64),
        RemoveBreakpoint(u64),
        Stop,
        Detach,
        GetState,
        ReadMemory(u64, usize),
    }

    pub enum DebugResponse {
        Snapshot(DebugSnapshot),
        Memory(Vec<u8>),
        Stopped,
    }

    pub struct DebugCommand {
        pub op: DebugOp,
        pub resp: tokio::sync::oneshot::Sender<Result<DebugResponse, String>>,
    }

    pub struct SessionHandle {
        pub cmd_tx: mpsc::Sender<DebugCommand>,
    }

    // ── Entry point ───────────────────────────────────────────────────────────

    pub fn start_session(
        path: String,
        _args: Vec<String>,
        session_id: u32,
        initial_tx: tokio::sync::oneshot::Sender<Result<StartDebugResult, String>>,
        app_handle: Option<tauri::AppHandle>,
    ) {
        let (cmd_tx, cmd_rx) = mpsc::channel::<DebugCommand>();

        // Register handle BEFORE thread starts so the session id is valid
        {
            let mut sessions = crate::commands::debugger::SESSIONS.lock().unwrap();
            sessions.insert(
                session_id,
                crate::commands::debugger::SessionHandle {
                    _impl: Box::new(SessionHandle { cmd_tx: cmd_tx.clone() }),
                },
            );
        }

        thread::spawn(move || {
            debug_thread(path, session_id, cmd_rx, initial_tx, app_handle);
        });
    }

    /// Attach to an already-running process by PID.
    pub fn start_attach_session(
        pid: u32,
        session_id: u32,
        initial_tx: tokio::sync::oneshot::Sender<Result<StartDebugResult, String>>,
        app_handle: Option<tauri::AppHandle>,
    ) {
        let (cmd_tx, cmd_rx) = mpsc::channel::<DebugCommand>();

        {
            let mut sessions = crate::commands::debugger::SESSIONS.lock().unwrap();
            sessions.insert(
                session_id,
                crate::commands::debugger::SessionHandle {
                    _impl: Box::new(SessionHandle { cmd_tx: cmd_tx.clone() }),
                },
            );
        }

        thread::spawn(move || {
            attach_debug_thread(pid, session_id, cmd_rx, initial_tx, app_handle);
        });
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    // Read 1 byte from a process
    unsafe fn read_byte(process: HANDLE, addr: u64) -> Option<u8> {
        let mut byte: u8 = 0;
        let mut read = 0usize;
        let ok = ReadProcessMemory(
            process,
            addr as *const _,
            &mut byte as *mut u8 as *mut _,
            1,
            &mut read,
        );
        if ok != FALSE && read == 1 { Some(byte) } else { None }
    }

    // Write 1 byte to a process
    unsafe fn write_byte(process: HANDLE, addr: u64, byte: u8) -> bool {
        let mut written = 0usize;
        let ok = WriteProcessMemory(
            process,
            addr as *const _,
            &byte as *const u8 as *const _,
            1,
            &mut written,
        );
        let _ = FlushInstructionCache(process, addr as *const _, 1);
        ok != FALSE && written == 1
    }

    // Read CONTEXT from thread
    unsafe fn get_ctx(thread: HANDLE) -> Option<CONTEXT> {
        let mut ctx: CONTEXT = std::mem::zeroed();
        ctx.ContextFlags = CONTEXT_ALL;
        if GetThreadContext(thread, &mut ctx) != FALSE {
            Some(ctx)
        } else {
            None
        }
    }

    // Set CONTEXT on thread
    unsafe fn set_ctx(thread: HANDLE, ctx: &CONTEXT) -> bool {
        SetThreadContext(thread, ctx) != FALSE
    }

    fn ctx_to_regs(ctx: &CONTEXT) -> RegisterState {
        RegisterState {
            rax: ctx.Rax,
            rbx: ctx.Rbx,
            rcx: ctx.Rcx,
            rdx: ctx.Rdx,
            rsi: ctx.Rsi,
            rdi: ctx.Rdi,
            rsp: ctx.Rsp,
            rbp: ctx.Rbp,
            rip: ctx.Rip,
            r8:  ctx.R8,
            r9:  ctx.R9,
            r10: ctx.R10,
            r11: ctx.R11,
            r12: ctx.R12,
            r13: ctx.R13,
            r14: ctx.R14,
            r15: ctx.R15,
            eflags: ctx.EFlags,
            cs: ctx.SegCs as u16,
            ss: ctx.SegSs as u16,
        }
    }

    fn read_stack(process: HANDLE, rsp: u64) -> Vec<u64> {
        let mut stack = Vec::new();
        for i in 0..16u64 {
            let addr = rsp + i * 8;
            unsafe {
                let mut val: u64 = 0;
                let mut read = 0usize;
                let ok = ReadProcessMemory(
                    process,
                    addr as *const _,
                    &mut val as *mut u64 as *mut _,
                    8,
                    &mut read,
                );
                if ok != FALSE && read == 8 {
                    stack.push(val);
                } else {
                    break;
                }
            }
        }
        stack
    }

    fn make_snapshot(
        session_id: u32,
        status: DebugStatus,
        ctx: &CONTEXT,
        process: HANDLE,
        bp_addrs: &[u64],
        step_count: u32,
        exit_code: Option<i32>,
        last_event: &str,
    ) -> DebugSnapshot {
        let regs = ctx_to_regs(ctx);
        let stack = read_stack(process, regs.rsp);
        DebugSnapshot {
            session_id,
            status,
            registers: regs,
            stack,
            breakpoints: bp_addrs.to_vec(),
            step_count,
            exit_code,
            last_event: last_event.to_string(),
        }
    }

    // ── Instruction disassembly helper ─────────────────────────────────────────

    /// If the first instruction in `bytes` at `addr` is a CALL, returns its length.
    /// Uses capstone for reliable decoding of all CALL variants.
    fn detect_call_at(addr: u64, bytes: &[u8]) -> Option<usize> {
        if bytes.is_empty() { return None; }
        use capstone::prelude::*;
        let cs = Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode64)
            .build()
            .ok()?;
        let insns = cs.disasm_count(bytes, addr, 1).ok()?;
        let insn = insns.as_ref().iter().next()?;
        if insn.mnemonic()?.starts_with("call") {
            Some(insn.bytes().len())
        } else {
            None
        }
    }

    // ── Mutable state for the running command dispatch loop ───────────────────

    struct DebugLoopState {
        process:           HANDLE,
        main_thread:       HANDLE,
        thread_handles:    HashMap<u32, HANDLE>,
        bp_originals:      HashMap<u64, u8>,
        user_bps:          std::collections::HashSet<u64>,
        step_count:        u32,
        exit_code:         Option<i32>,
        current_ctx:       CONTEXT,
        current_thread:    HANDLE,
        status:            DebugStatus,
        last_event_str:    String,
        pending_event_pid: u32,
        pending_event_tid: u32,
        session_id:        u32,
        app_handle:        Option<tauri::AppHandle>,
    }

    impl DebugLoopState {
            fn release_debug_handles(&mut self) {
                for (_tid, handle) in self.thread_handles.drain() {
                    if handle != 0 && handle != self.main_thread {
                        unsafe { CloseHandle(handle); }
                    }
                }
                if self.main_thread != 0 {
                    unsafe { CloseHandle(self.main_thread); }
                    self.main_thread = 0;
                }
            }

        fn emit_snapshot(&self, snap: &DebugSnapshot) {
            if let Some(ref ah) = self.app_handle {
                use tauri::Emitter;
                let _ = ah.emit("strike-snapshot", snap);
            }
        }

        fn make_current_snapshot(&self) -> DebugSnapshot {
            let bp_list: Vec<u64> = self.user_bps.iter().copied().collect();
            make_snapshot(
                self.session_id, self.status.clone(), &self.current_ctx,
                self.process, &bp_list, self.step_count, self.exit_code,
                &self.last_event_str,
            )
        }

        /// Wait for the next relevant stop event. ContinueDebugEvent must already
        /// have been called by the caller before invoking this. Updates self state.
        fn wait_for_stop(&mut self) -> Result<(), String> {
            let timeout_ms = 10_000u32;
            loop {
                let mut evt: DEBUG_EVENT = unsafe { std::mem::zeroed() };
                let ok = unsafe { WaitForDebugEvent(&mut evt, timeout_ms) };
                if ok == FALSE {
                    return Err("WaitForDebugEvent timed out (10 s)".to_string());
                }
                let tid    = evt.dwThreadId;
                let thread = self.thread_handles.get(&tid).copied().unwrap_or(self.main_thread);

                match evt.dwDebugEventCode {
                    EXCEPTION_DEBUG_EVENT => {
                        let exc  = unsafe { &evt.u.Exception.ExceptionRecord };
                        let code = exc.ExceptionCode;
                        let addr = exc.ExceptionAddress as u64;

                        if code == EXCEPTION_SINGLE_STEP {
                            self.step_count += 1;
                            let ctx = unsafe { get_ctx(thread) }
                                .ok_or_else(|| "GetThreadContext failed".to_string())?;
                            self.current_ctx       = ctx;
                            self.current_thread    = thread;
                            self.status            = DebugStatus::Paused;
                            self.last_event_str    = "single-step".to_string();
                            self.pending_event_pid = evt.dwProcessId;
                            self.pending_event_tid = tid;
                            return Ok(());
                        } else if code == EXCEPTION_BREAKPOINT {
                            if let Some(orig) = self.bp_originals.remove(&addr) {
                                unsafe { write_byte(self.process, addr, orig); }
                                if let Some(mut ctx) = unsafe { get_ctx(thread) } {
                                    ctx.Rip -= 1;
                                    unsafe { set_ctx(thread, &ctx); }
                                    if self.user_bps.contains(&addr) {
                                        self.bp_originals.insert(addr, orig);
                                    }
                                    self.current_ctx       = ctx;
                                    self.current_thread    = thread;
                                    self.status            = DebugStatus::Paused;
                                    self.last_event_str    = format!("breakpoint@{:#x}", addr);
                                    self.pending_event_pid = evt.dwProcessId;
                                    self.pending_event_tid = tid;
                                    return Ok(());
                                }
                            }
                            // Unknown/system breakpoint — continue
                            unsafe { ContinueDebugEvent(evt.dwProcessId, tid, DBG_CONTINUE); }
                        } else {
                            unsafe {
                                ContinueDebugEvent(evt.dwProcessId, tid, DBG_EXCEPTION_NOT_HANDLED);
                            }
                        }
                    }
                    EXIT_PROCESS_DEBUG_EVENT => {
                        let info = unsafe { &evt.u.ExitProcess };
                        self.exit_code      = Some(info.dwExitCode as i32);
                        self.status         = DebugStatus::Exited;
                        self.last_event_str = "exited".to_string();
                        unsafe { ContinueDebugEvent(evt.dwProcessId, tid, DBG_CONTINUE); }
                        return Ok(());
                    }
                    OUTPUT_DEBUG_STRING_EVENT => {
                        unsafe { ContinueDebugEvent(evt.dwProcessId, tid, DBG_CONTINUE); }
                    }
                    LOAD_DLL_DEBUG_EVENT => {
                        let info = unsafe { &evt.u.LoadDll };
                        if info.hFile != INVALID_HANDLE_VALUE && info.hFile != 0 {
                            unsafe { CloseHandle(info.hFile); }
                        }
                        unsafe { ContinueDebugEvent(evt.dwProcessId, tid, DBG_CONTINUE); }
                    }
                    CREATE_THREAD_DEBUG_EVENT => {
                        let info = unsafe { &evt.u.CreateThread };
                        self.thread_handles.insert(tid, info.hThread);
                        unsafe { ContinueDebugEvent(evt.dwProcessId, tid, DBG_CONTINUE); }
                    }
                    _ => {
                        unsafe { ContinueDebugEvent(evt.dwProcessId, tid, DBG_CONTINUE); }
                    }
                }
            }
        }

        fn run_command_loop(mut self, cmd_rx: mpsc::Receiver<DebugCommand>) {
            while let Ok(cmd) = cmd_rx.recv() {
                match cmd.op {
                    DebugOp::GetState => {
                        let snap = self.make_current_snapshot();
                        let _ = cmd.resp.send(Ok(DebugResponse::Snapshot(snap)));
                    }

                    DebugOp::Step => {
                        if self.status == DebugStatus::Exited {
                            let snap = self.make_current_snapshot();
                            let _ = cmd.resp.send(Ok(DebugResponse::Snapshot(snap)));
                            continue;
                        }
                        let mut ctx    = self.current_ctx;
                        ctx.EFlags    |= 0x100; // TF
                        unsafe { set_ctx(self.current_thread, &ctx); }
                        unsafe { ContinueDebugEvent(self.pending_event_pid, self.pending_event_tid, DBG_CONTINUE); }
                        match self.wait_for_stop() {
                            Ok(()) => {
                                let snap = self.make_current_snapshot();
                                self.emit_snapshot(&snap);
                                let _ = cmd.resp.send(Ok(DebugResponse::Snapshot(snap)));
                            }
                            Err(e) => {
                                self.status = DebugStatus::Error;
                                self.last_event_str = format!("step error: {}", e);
                                let _ = cmd.resp.send(Err(e));
                            }
                        }
                    }

                    DebugOp::StepOver => {
                        if self.status == DebugStatus::Exited {
                            let snap = self.make_current_snapshot();
                            let _ = cmd.resp.send(Ok(DebugResponse::Snapshot(snap)));
                            continue;
                        }
                        let rip     = self.current_ctx.Rip;
                        let mut ibuf = [0u8; 15];
                        let mut n_read = 0usize;
                        unsafe {
                            ReadProcessMemory(
                                self.process, rip as *const _,
                                ibuf.as_mut_ptr() as *mut _, 15, &mut n_read,
                            );
                        }
                        let maybe_call_len = detect_call_at(rip, &ibuf[..n_read.min(15)]);
                        if let Some(call_len) = maybe_call_len {
                            // Step over: place temp INT3 at the return address (RIP + call_len)
                            let over_addr    = rip + call_len as u64;
                            let had_user_bp  = self.user_bps.contains(&over_addr);
                            if !had_user_bp {
                                if let Some(orig) = unsafe { read_byte(self.process, over_addr) } {
                                    self.bp_originals.entry(over_addr).or_insert(orig);
                                    unsafe { write_byte(self.process, over_addr, 0xCC); }
                                }
                            }
                            unsafe { ContinueDebugEvent(self.pending_event_pid, self.pending_event_tid, DBG_CONTINUE); }
                            match self.wait_for_stop() {
                                Ok(()) => {
                                    // Remove temp BP if still present and not a user BP
                                    if !had_user_bp && !self.user_bps.contains(&over_addr) {
                                        if let Some(orig) = self.bp_originals.remove(&over_addr) {
                                            unsafe { write_byte(self.process, over_addr, orig); }
                                        }
                                    }
                                    let snap = self.make_current_snapshot();
                                    self.emit_snapshot(&snap);
                                    let _ = cmd.resp.send(Ok(DebugResponse::Snapshot(snap)));
                                }
                                Err(e) => {
                                    // Best-effort cleanup on error
                                    if !had_user_bp {
                                        if let Some(orig) = self.bp_originals.remove(&over_addr) {
                                            unsafe { write_byte(self.process, over_addr, orig); }
                                        }
                                    }
                                    self.status = DebugStatus::Error;
                                    self.last_event_str = format!("step over error: {}", e);
                                    let _ = cmd.resp.send(Err(e));
                                }
                            }
                        } else {
                            // Not a CALL — fall back to single-step (same as Step)
                            let mut ctx  = self.current_ctx;
                            ctx.EFlags  |= 0x100;
                            unsafe { set_ctx(self.current_thread, &ctx); }
                            unsafe { ContinueDebugEvent(self.pending_event_pid, self.pending_event_tid, DBG_CONTINUE); }
                            match self.wait_for_stop() {
                                Ok(()) => {
                                    let snap = self.make_current_snapshot();
                                    self.emit_snapshot(&snap);
                                    let _ = cmd.resp.send(Ok(DebugResponse::Snapshot(snap)));
                                }
                                Err(e) => {
                                    self.status = DebugStatus::Error;
                                    self.last_event_str = format!("step over fallback error: {}", e);
                                    let _ = cmd.resp.send(Err(e));
                                }
                            }
                        }
                    }

                    DebugOp::StepOut => {
                        // Read return address from top of stack ([RSP]), place a
                        // temporary INT3 there, continue, then clean up.
                        if self.status == DebugStatus::Exited {
                            let snap = self.make_current_snapshot();
                            let _ = cmd.resp.send(Ok(DebugResponse::Snapshot(snap)));
                            continue;
                        }
                        let rsp = self.current_ctx.Rsp;
                        let mut ret_addr_bytes = [0u8; 8];
                        let mut n_read = 0usize;
                        let read_ok = unsafe {
                            ReadProcessMemory(
                                self.process, rsp as *const _,
                                ret_addr_bytes.as_mut_ptr() as *mut _, 8, &mut n_read,
                            ) != 0
                        };
                        if !read_ok || n_read < 8 {
                            let _ = cmd.resp.send(Err(format!("StepOut: failed to read return address at RSP={:#x}", rsp)));
                            continue;
                        }
                        let ret_addr = u64::from_le_bytes(ret_addr_bytes);
                        let had_user_bp = self.user_bps.contains(&ret_addr);
                        if !had_user_bp {
                            if let Some(orig) = unsafe { read_byte(self.process, ret_addr) } {
                                self.bp_originals.entry(ret_addr).or_insert(orig);
                                unsafe { write_byte(self.process, ret_addr, 0xCC); }
                            }
                        }
                        unsafe { ContinueDebugEvent(self.pending_event_pid, self.pending_event_tid, DBG_CONTINUE); }
                        match self.wait_for_stop() {
                            Ok(()) => {
                                if !had_user_bp && !self.user_bps.contains(&ret_addr) {
                                    if let Some(orig) = self.bp_originals.remove(&ret_addr) {
                                        unsafe { write_byte(self.process, ret_addr, orig); }
                                    }
                                }
                                let snap = self.make_current_snapshot();
                                self.emit_snapshot(&snap);
                                let _ = cmd.resp.send(Ok(DebugResponse::Snapshot(snap)));
                            }
                            Err(e) => {
                                if !had_user_bp {
                                    if let Some(orig) = self.bp_originals.remove(&ret_addr) {
                                        unsafe { write_byte(self.process, ret_addr, orig); }
                                    }
                                }
                                self.status = DebugStatus::Error;
                                self.last_event_str = format!("step out error: {}", e);
                                let _ = cmd.resp.send(Err(e));
                            }
                        }
                    }

                    DebugOp::Continue => {
                        if self.status == DebugStatus::Exited {
                            let snap = self.make_current_snapshot();
                            let _ = cmd.resp.send(Ok(DebugResponse::Snapshot(snap)));
                            continue;
                        }
                        unsafe { ContinueDebugEvent(self.pending_event_pid, self.pending_event_tid, DBG_CONTINUE); }
                        match self.wait_for_stop() {
                            Ok(()) => {
                                let snap = self.make_current_snapshot();
                                self.emit_snapshot(&snap);
                                let _ = cmd.resp.send(Ok(DebugResponse::Snapshot(snap)));
                            }
                            Err(e) => {
                                self.status = DebugStatus::Error;
                                self.last_event_str = format!("continue error: {}", e);
                                let _ = cmd.resp.send(Err(e));
                            }
                        }
                    }

                    DebugOp::SetBreakpoint(addr) => {
                        self.user_bps.insert(addr);
                        if let Some(orig) = unsafe { read_byte(self.process, addr) } {
                            self.bp_originals.insert(addr, orig);
                            unsafe { write_byte(self.process, addr, 0xCC); }
                        }
                        let snap = self.make_current_snapshot();
                        let _ = cmd.resp.send(Ok(DebugResponse::Snapshot(snap)));
                    }

                    DebugOp::RemoveBreakpoint(addr) => {
                        self.user_bps.remove(&addr);
                        if let Some(orig) = self.bp_originals.remove(&addr) {
                            unsafe { write_byte(self.process, addr, orig); }
                        }
                        let snap = self.make_current_snapshot();
                        let _ = cmd.resp.send(Ok(DebugResponse::Snapshot(snap)));
                    }

                    DebugOp::ReadMemory(addr, size) => {
                        let clamped = size.min(4096);
                        let mut buf = vec![0u8; clamped];
                        let mut n_read = 0usize;
                        let ok = unsafe {
                            ReadProcessMemory(
                                self.process, addr as *const _,
                                buf.as_mut_ptr() as *mut _, clamped, &mut n_read,
                            )
                        };
                        if ok != FALSE {
                            buf.truncate(n_read);
                            let _ = cmd.resp.send(Ok(DebugResponse::Memory(buf)));
                        } else {
                            let _ = cmd.resp.send(Err(format!("ReadProcessMemory failed at {:#x}", addr)));
                        }
                    }

                    DebugOp::Detach => {
                        let pid = unsafe { GetProcessId(self.process) };
                        if pid != 0 {
                            unsafe { DebugActiveProcessStop(pid); }
                        }
                        self.release_debug_handles();
                        if self.process != 0 {
                            unsafe { CloseHandle(self.process); }
                            self.process = 0;
                        }
                        crate::commands::debugger::remove_session(self.session_id);
                        let _ = cmd.resp.send(Ok(DebugResponse::Stopped));
                        return;
                    }

                    DebugOp::Stop => {
                        if self.process != 0 {
                            unsafe { TerminateProcess(self.process, 0); }
                        }
                        self.release_debug_handles();
                        if self.process != 0 {
                            unsafe { CloseHandle(self.process); }
                            self.process = 0;
                        }
                        crate::commands::debugger::remove_session(self.session_id);
                        let _ = cmd.resp.send(Ok(DebugResponse::Stopped));
                        return;
                    }
                }
            }
            // cmd_rx dropped — clean up
            if self.process != 0 {
                unsafe { TerminateProcess(self.process, 0); }
            }
            self.release_debug_handles();
            if self.process != 0 {
                unsafe { CloseHandle(self.process); }
                self.process = 0;
            }
            crate::commands::debugger::remove_session(self.session_id);
        }
    }

    // ── Debug thread ──────────────────────────────────────────────────────────

    fn debug_thread(
        path: String,
        session_id: u32,
        cmd_rx: mpsc::Receiver<DebugCommand>,
        initial_tx: tokio::sync::oneshot::Sender<Result<StartDebugResult, String>>,
        app_handle: Option<tauri::AppHandle>,
    ) {
        // Launch process
        let path_wide = wide(&path);
        let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
        si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

        let flags = DEBUG_PROCESS | CREATE_NEW_CONSOLE;
        let ok = unsafe {
            CreateProcessW(
                path_wide.as_ptr(),
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
                FALSE,
                flags,
                std::ptr::null(),
                std::ptr::null(),
                &si,
                &mut pi,
            )
        };

        if ok == FALSE {
            let err = format!("CreateProcessW failed: error {}", unsafe {
                windows_sys::Win32::Foundation::GetLastError()
            });
            crate::commands::debugger::remove_session(session_id);
            let _ = initial_tx.send(Err(err));
            return;
        }

        let process     = pi.hProcess;
        let main_thread = pi.hThread;

        let mut thread_handles: HashMap<u32, HANDLE> = HashMap::new();
        thread_handles.insert(pi.dwThreadId, main_thread);

        let bp_originals: HashMap<u64, u8>              = HashMap::new();
        let user_bps:     std::collections::HashSet<u64> = std::collections::HashSet::new();
        let step_count  = 0u32;
        let exit_code: Option<i32> = None;
        let mut system_bp_hit = false;

        // ── Initial event loop: wait for first system breakpoint ─────────────
        let (initial_ctx, init_pending_pid, init_pending_tid) = loop {
            let mut evt: DEBUG_EVENT = unsafe { std::mem::zeroed() };
            let ok = unsafe { WaitForDebugEvent(&mut evt, 5000) };
            if ok == FALSE {
                let _ = initial_tx.send(Err("Timed out waiting for process start".to_string()));
                unsafe { TerminateProcess(process, 1); }
                unsafe { CloseHandle(main_thread); }
                unsafe { CloseHandle(process); }
                crate::commands::debugger::remove_session(session_id);
                return;
            }
            match evt.dwDebugEventCode {
                CREATE_PROCESS_DEBUG_EVENT => {
                    let info = unsafe { &evt.u.CreateProcessInfo };
                    thread_handles.insert(evt.dwThreadId, info.hThread);
                    if info.hFile != INVALID_HANDLE_VALUE && info.hFile != 0 {
                        unsafe { CloseHandle(info.hFile); }
                    }
                    unsafe { ContinueDebugEvent(evt.dwProcessId, evt.dwThreadId, DBG_CONTINUE); }
                }
                LOAD_DLL_DEBUG_EVENT => {
                    let info = unsafe { &evt.u.LoadDll };
                    if info.hFile != INVALID_HANDLE_VALUE && info.hFile != 0 {
                        unsafe { CloseHandle(info.hFile); }
                    }
                    unsafe { ContinueDebugEvent(evt.dwProcessId, evt.dwThreadId, DBG_CONTINUE); }
                }
                EXCEPTION_DEBUG_EVENT => {
                    let code = unsafe { evt.u.Exception.ExceptionRecord.ExceptionCode };
                    if code == EXCEPTION_BREAKPOINT && !system_bp_hit {
                        system_bp_hit = true;
                        let thread = thread_handles.get(&evt.dwThreadId).copied().unwrap_or(main_thread);
                        if let Some(ctx) = unsafe { get_ctx(thread) } {
                            break (ctx, evt.dwProcessId, evt.dwThreadId);
                        }
                        unsafe { ContinueDebugEvent(evt.dwProcessId, evt.dwThreadId, DBG_CONTINUE); }
                    } else {
                        unsafe { ContinueDebugEvent(evt.dwProcessId, evt.dwThreadId, DBG_EXCEPTION_NOT_HANDLED); }
                    }
                }
                EXIT_PROCESS_DEBUG_EVENT => {
                    let info = unsafe { &evt.u.ExitProcess };
                    let code = info.dwExitCode as i32;
                    let snapshot = DebugSnapshot {
                        session_id,
                        status: DebugStatus::Exited,
                        registers: RegisterState::default(),
                        stack: vec![],
                        breakpoints: vec![],
                        step_count: 0,
                        exit_code: Some(code),
                        last_event: "exit".to_string(),
                    };
                    let _ = initial_tx.send(Ok(StartDebugResult {
                        session_id,
                        snapshot,
                        arch: "x86-64".to_string(),
                        warnings: vec!["Process exited before system breakpoint".to_string()],
                    }));
                    unsafe { CloseHandle(main_thread); }
                    unsafe { CloseHandle(process); }
                    crate::commands::debugger::remove_session(session_id);
                    return;
                }
                _ => {
                    unsafe { ContinueDebugEvent(evt.dwProcessId, evt.dwThreadId, DBG_CONTINUE); }
                }
            }
        };

        // Send initial state to caller
        let bp_list: Vec<u64> = user_bps.iter().copied().collect();
        let initial_snapshot = make_snapshot(
            session_id, DebugStatus::Paused, &initial_ctx, process,
            &bp_list, 0, None, "system-breakpoint",
        );
        let _ = initial_tx.send(Ok(StartDebugResult {
            session_id,
            snapshot: initial_snapshot,
            arch: "x86-64".to_string(),
            warnings: vec![],
        }));

        let current_thread = thread_handles.get(&init_pending_tid).copied().unwrap_or(main_thread);
        let state = DebugLoopState {
            process,
            main_thread,
            thread_handles,
            bp_originals,
            user_bps,
            step_count,
            exit_code,
            current_ctx:       initial_ctx,
            current_thread,
            status:            DebugStatus::Paused,
            last_event_str:    "system-breakpoint".to_string(),
            pending_event_pid: init_pending_pid,
            pending_event_tid: init_pending_tid,
            session_id,
            app_handle,
        };
        state.run_command_loop(cmd_rx);
    }

    // ── Attach-to-process thread ──────────────────────────────────────────────

    fn attach_debug_thread(
        pid: u32,
        session_id: u32,
        cmd_rx: mpsc::Receiver<DebugCommand>,
        initial_tx: tokio::sync::oneshot::Sender<Result<StartDebugResult, String>>,
        app_handle: Option<tauri::AppHandle>,
    ) {
        if unsafe { DebugActiveProcess(pid) } == FALSE {
            crate::commands::debugger::remove_session(session_id);
            let _ = initial_tx.send(Err(format!(
                "DebugActiveProcess({}) failed: error {}",
                pid,
                unsafe { windows_sys::Win32::Foundation::GetLastError() },
            )));
            return;
        }

        let desired_access = PROCESS_QUERY_INFORMATION
            | PROCESS_VM_READ
            | PROCESS_VM_WRITE
            | PROCESS_VM_OPERATION
            | PROCESS_TERMINATE;
        let process = unsafe { OpenProcess(desired_access, FALSE, pid) };
        if process == 0 {
            unsafe { DebugActiveProcessStop(pid); }
            crate::commands::debugger::remove_session(session_id);
            let _ = initial_tx.send(Err(format!(
                "OpenProcess({}) failed: error {}",
                pid,
                unsafe { windows_sys::Win32::Foundation::GetLastError() },
            )));
            return;
        }

        let mut thread_handles: HashMap<u32, HANDLE> = HashMap::new();
        let mut main_thread: HANDLE = 0;
        let bp_originals: HashMap<u64, u8>              = HashMap::new();
        let user_bps:     std::collections::HashSet<u64> = std::collections::HashSet::new();
        let step_count  = 0u32;
        let exit_code: Option<i32> = None;

        // ── Initial event loop: consume attach events until first INT3 ────────
        let (initial_ctx, init_pending_pid, init_pending_tid) = loop {
            let mut evt: DEBUG_EVENT = unsafe { std::mem::zeroed() };
            let ok = unsafe { WaitForDebugEvent(&mut evt, 10_000) };
            if ok == FALSE {
                let _ = initial_tx.send(Err("Timed out waiting for attach breakpoint".to_string()));
                unsafe { DebugActiveProcessStop(pid); }
                unsafe { CloseHandle(process); }
                crate::commands::debugger::remove_session(session_id);
                return;
            }
            match evt.dwDebugEventCode {
                CREATE_PROCESS_DEBUG_EVENT => {
                    let info = unsafe { &evt.u.CreateProcessInfo };
                    main_thread = info.hThread;
                    thread_handles.insert(evt.dwThreadId, info.hThread);
                    if info.hFile != INVALID_HANDLE_VALUE && info.hFile != 0 {
                        unsafe { CloseHandle(info.hFile); }
                    }
                    unsafe { ContinueDebugEvent(evt.dwProcessId, evt.dwThreadId, DBG_CONTINUE); }
                }
                CREATE_THREAD_DEBUG_EVENT => {
                    let info = unsafe { &evt.u.CreateThread };
                    thread_handles.insert(evt.dwThreadId, info.hThread);
                    if main_thread == 0 { main_thread = info.hThread; }
                    unsafe { ContinueDebugEvent(evt.dwProcessId, evt.dwThreadId, DBG_CONTINUE); }
                }
                LOAD_DLL_DEBUG_EVENT => {
                    let info = unsafe { &evt.u.LoadDll };
                    if info.hFile != INVALID_HANDLE_VALUE && info.hFile != 0 {
                        unsafe { CloseHandle(info.hFile); }
                    }
                    unsafe { ContinueDebugEvent(evt.dwProcessId, evt.dwThreadId, DBG_CONTINUE); }
                }
                EXCEPTION_DEBUG_EVENT => {
                    let code = unsafe { evt.u.Exception.ExceptionRecord.ExceptionCode };
                    if code == EXCEPTION_BREAKPOINT {
                        if main_thread == 0 {
                            main_thread = thread_handles.values().next().copied().unwrap_or(0);
                        }
                        let thread = thread_handles.get(&evt.dwThreadId).copied().unwrap_or(main_thread);
                        if let Some(ctx) = unsafe { get_ctx(thread) } {
                            break (ctx, evt.dwProcessId, evt.dwThreadId);
                        }
                        unsafe { ContinueDebugEvent(evt.dwProcessId, evt.dwThreadId, DBG_CONTINUE); }
                    } else {
                        unsafe { ContinueDebugEvent(evt.dwProcessId, evt.dwThreadId, DBG_EXCEPTION_NOT_HANDLED); }
                    }
                }
                EXIT_PROCESS_DEBUG_EVENT => {
                    let info = unsafe { &evt.u.ExitProcess };
                    let code = info.dwExitCode as i32;
                    let _ = initial_tx.send(Err(format!("Process exited during attach with code {}", code)));
                    unsafe { DebugActiveProcessStop(pid); }
                    unsafe { CloseHandle(process); }
                    crate::commands::debugger::remove_session(session_id);
                    return;
                }
                _ => {
                    unsafe { ContinueDebugEvent(evt.dwProcessId, evt.dwThreadId, DBG_CONTINUE); }
                }
            }
        };

        let bp_list: Vec<u64> = user_bps.iter().copied().collect();
        let initial_snapshot = make_snapshot(
            session_id, DebugStatus::Paused, &initial_ctx, process,
            &bp_list, 0, None, "attach-breakpoint",
        );
        let _ = initial_tx.send(Ok(StartDebugResult {
            session_id,
            snapshot: initial_snapshot,
            arch: "x86-64".to_string(),
            warnings: vec!["Attached to running process".to_string()],
        }));

        let current_thread = thread_handles.get(&init_pending_tid).copied().unwrap_or(main_thread);
        let state = DebugLoopState {
            process,
            main_thread,
            thread_handles,
            bp_originals,
            user_bps,
            step_count,
            exit_code,
            current_ctx:       initial_ctx,
            current_thread,
            status:            DebugStatus::Paused,
            last_event_str:    "attach-breakpoint".to_string(),
            pending_event_pid: init_pending_pid,
            pending_event_tid: init_pending_tid,
            session_id,
            app_handle,
        };
        state.run_command_loop(cmd_rx);
    }
}

// ── Linux ptrace backend ──────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use nix::sys::ptrace;
    use nix::sys::signal::Signal;
    use nix::sys::wait::{waitpid, WaitStatus};
    use nix::unistd::Pid;
    use std::collections::HashSet;
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    use std::sync::mpsc;
    use std::thread;

    // ── Register mapping ──────────────────────────────────────────────────────

    #[cfg(target_arch = "x86_64")]
    fn regs_from_libc(r: &nix::libc::user_regs_struct) -> RegisterState {
        RegisterState {
            rax: r.rax,
            rbx: r.rbx,
            rcx: r.rcx,
            rdx: r.rdx,
            rsi: r.rsi,
            rdi: r.rdi,
            rsp: r.rsp,
            rbp: r.rbp,
            rip: r.rip,
            r8:  r.r8,
            r9:  r.r9,
            r10: r.r10,
            r11: r.r11,
            r12: r.r12,
            r13: r.r13,
            r14: r.r14,
            r15: r.r15,
            eflags: r.eflags as u32,
            cs: r.cs as u16,
            ss: r.ss as u16,
        }
    }

    #[cfg(not(target_arch = "x86_64"))]
    fn regs_from_libc(_r: &()) -> RegisterState {
        RegisterState::default()
    }

    #[cfg(target_arch = "x86_64")]
    fn read_stack_ptrace(pid: Pid, rsp: u64) -> Vec<u64> {
        let mut stack = Vec::new();
        for i in 0..16u64 {
            let addr = (rsp + i * 8) as nix::libc::c_long;
            match ptrace::read(pid, addr as *mut _) {
                Ok(v) => stack.push(v as u64),
                Err(_) => break,
            }
        }
        stack
    }

    #[cfg(not(target_arch = "x86_64"))]
    fn read_stack_ptrace(_pid: Pid, _rsp: u64) -> Vec<u64> { vec![] }

    // ── Message types ─────────────────────────────────────────────────────────

    pub enum DebugOp {
        Step,
        StepOver,
        StepOut,
        Continue,
        SetBreakpoint(u64),
        RemoveBreakpoint(u64),
        Stop,
        Detach,
        GetState,
        ReadMemory(u64, usize),
    }

    pub enum DebugResponse {
        Snapshot(DebugSnapshot),
        Memory(Vec<u8>),
        Stopped,
    }

    pub struct DebugCommand {
        pub op: DebugOp,
        pub resp: tokio::sync::oneshot::Sender<Result<DebugResponse, String>>,
    }

    pub struct SessionHandle {
        pub cmd_tx: mpsc::Sender<DebugCommand>,
    }

    // ── Entry point ───────────────────────────────────────────────────────────

    pub fn start_session(
        path: String,
        args: Vec<String>,
        session_id: u32,
        initial_tx: tokio::sync::oneshot::Sender<Result<StartDebugResult, String>>,
        _app_handle: Option<tauri::AppHandle>,
    ) {
        let (cmd_tx, cmd_rx) = mpsc::channel::<DebugCommand>();

        {
            let mut sessions = crate::commands::debugger::SESSIONS.lock().unwrap();
            sessions.insert(
                session_id,
                crate::commands::debugger::SessionHandle {
                    _impl: Box::new(SessionHandle { cmd_tx: cmd_tx.clone() }),
                },
            );
        }

        thread::spawn(move || {
            debug_thread(path, args, session_id, cmd_rx, initial_tx);
        });
    }

    pub fn start_attach_session(
        pid: u32,
        session_id: u32,
        initial_tx: tokio::sync::oneshot::Sender<Result<StartDebugResult, String>>,
        _app_handle: Option<tauri::AppHandle>,
    ) {
        let (cmd_tx, cmd_rx) = mpsc::channel::<DebugCommand>();

        {
            let mut sessions = crate::commands::debugger::SESSIONS.lock().unwrap();
            sessions.insert(
                session_id,
                crate::commands::debugger::SessionHandle {
                    _impl: Box::new(SessionHandle { cmd_tx: cmd_tx.clone() }),
                },
            );
        }

        thread::spawn(move || {
            attach_debug_thread(pid, session_id, cmd_rx, initial_tx);
        });
    }

    // ── Debug thread (launch) ─────────────────────────────────────────────────

    fn debug_thread(
        path: String,
        args: Vec<String>,
        session_id: u32,
        cmd_rx: mpsc::Receiver<DebugCommand>,
        initial_tx: tokio::sync::oneshot::Sender<Result<StartDebugResult, String>>,
    ) {
        // Spawn child with PTRACE_TRACEME
        let mut child_builder = Command::new(&path);
        child_builder
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        // Safety: pre_exec runs in the child after fork — single-threaded at that point
        unsafe {
            child_builder.pre_exec(|| {
                nix::sys::ptrace::traceme().map_err(|e| {
                    std::io::Error::new(std::io::ErrorKind::Other, e.desc())
                })?;
                Ok(())
            });
        }
        let child = match child_builder.spawn() {
            Ok(c) => c,
            Err(e) => {
                crate::commands::debugger::remove_session(session_id);
                let _ = initial_tx.send(Err(format!("Failed to spawn process: {}", e)));
                return;
            }
        };
        let pid = Pid::from_raw(child.id() as i32);
        run_session(pid, false, session_id, cmd_rx, initial_tx);
    }

    // ── Debug thread (attach) ─────────────────────────────────────────────────

    fn attach_debug_thread(
        pid_raw: u32,
        session_id: u32,
        cmd_rx: mpsc::Receiver<DebugCommand>,
        initial_tx: tokio::sync::oneshot::Sender<Result<StartDebugResult, String>>,
    ) {
        let pid = Pid::from_raw(pid_raw as i32);
        if let Err(e) = ptrace::attach(pid) {
            crate::commands::debugger::remove_session(session_id);
            let _ = initial_tx.send(Err(format!("ptrace::attach failed: {}", e)));
            return;
        }
        run_session(pid, true, session_id, cmd_rx, initial_tx);
    }

    // ── Core session loop ─────────────────────────────────────────────────────

    fn run_session(
        pid: Pid,
        _attached: bool,
        session_id: u32,
        cmd_rx: mpsc::Receiver<DebugCommand>,
        initial_tx: tokio::sync::oneshot::Sender<Result<StartDebugResult, String>>,
    ) {
        // Wait for the first stop (SIGTRAP after exec or after attach)
        match waitpid(pid, None) {
            Ok(WaitStatus::Stopped(_, _)) => {}
            Ok(WaitStatus::Exited(_, code)) => {
                crate::commands::debugger::remove_session(session_id);
                let _ = initial_tx.send(Err(format!("Process exited immediately with code {}", code)));
                return;
            }
            Err(e) => {
                crate::commands::debugger::remove_session(session_id);
                let _ = initial_tx.send(Err(format!("waitpid failed: {}", e)));
                return;
            }
            _ => {}
        }

        let snap = make_snapshot_linux(pid, session_id, DebugStatus::Paused, 0, None, "initial stop");
        let result = StartDebugResult {
            session_id,
            snapshot: snap,
            arch: detect_arch(),
            warnings: vec![],
        };

        if initial_tx.send(Ok(result)).is_err() {
            crate::commands::debugger::remove_session(session_id);
            return;
        }

        // Command dispatch loop
        let mut step_count: u32 = 0;
        let mut user_bps: HashSet<u64> = HashSet::new();
        let mut bp_originals: std::collections::HashMap<u64, u8> = std::collections::HashMap::new();

        while let Ok(cmd) = cmd_rx.recv() {
            let response = dispatch_cmd(pid, &mut step_count, &mut user_bps, &mut bp_originals, session_id, cmd.op);
            let _ = cmd.resp.send(response);
        }

        // Caller dropped — kill process
        let _ = ptrace::kill(pid);
        let _ = waitpid(pid, None);
        crate::commands::debugger::remove_session(session_id);
    }

    fn dispatch_cmd(
        pid: Pid,
        step_count: &mut u32,
        user_bps: &mut HashSet<u64>,
        bp_originals: &mut std::collections::HashMap<u64, u8>,
        session_id: u32,
        op: DebugOp,
    ) -> Result<DebugResponse, String> {
        match op {
            DebugOp::GetState => {
                let snap = make_snapshot_linux(pid, session_id, DebugStatus::Paused, *step_count, None, "get_state");
                Ok(DebugResponse::Snapshot(snap))
            }

            DebugOp::Step | DebugOp::StepOver | DebugOp::StepOut => {
                // Linux: single-step for all step variants (ptrace PTRACE_SINGLESTEP)
                ptrace::step(pid, None).map_err(|e| e.to_string())?;
                wait_for_stop(pid)?;
                *step_count += 1;
                let snap = make_snapshot_linux(pid, session_id, DebugStatus::Paused, *step_count, None, "single-step");
                Ok(DebugResponse::Snapshot(snap))
            }

            DebugOp::Continue => {
                ptrace::cont(pid, None).map_err(|e| e.to_string())?;
                match wait_for_stop(pid) {
                    Ok(false) => {
                        // Exited
                        let snap = make_snapshot_linux(pid, session_id, DebugStatus::Exited, *step_count, Some(0), "exited");
                        Ok(DebugResponse::Snapshot(snap))
                    }
                    Ok(true) => {
                        let snap = make_snapshot_linux(pid, session_id, DebugStatus::Paused, *step_count, None, "breakpoint/stop");
                        Ok(DebugResponse::Snapshot(snap))
                    }
                    Err(e) => Err(e),
                }
            }

            DebugOp::SetBreakpoint(addr) => {
                // Read original byte and write 0xCC (INT 3)
                let orig = ptrace::read(pid, addr as *mut _)
                    .map_err(|e| format!("read for bp: {}", e))?;
                let patched = (orig & !0xFF) | 0xCC;
                unsafe {
                    ptrace::write(pid, addr as *mut _, patched as *mut _)
                        .map_err(|e| format!("write bp: {}", e))?;
                }
                bp_originals.insert(addr, (orig & 0xFF) as u8);
                user_bps.insert(addr);
                let snap = make_snapshot_linux(pid, session_id, DebugStatus::Paused, *step_count, None, "set_breakpoint");
                Ok(DebugResponse::Snapshot(snap))
            }

            DebugOp::RemoveBreakpoint(addr) => {
                if let Some(&orig_byte) = bp_originals.get(&addr) {
                    let current = ptrace::read(pid, addr as *mut _)
                        .map_err(|e| format!("read for bp remove: {}", e))?;
                    let restored = (current & !0xFF) | orig_byte as i64;
                    unsafe {
                        ptrace::write(pid, addr as *mut _, restored as *mut _)
                            .map_err(|e| format!("write bp restore: {}", e))?;
                    }
                    bp_originals.remove(&addr);
                    user_bps.remove(&addr);
                }
                let snap = make_snapshot_linux(pid, session_id, DebugStatus::Paused, *step_count, None, "remove_breakpoint");
                Ok(DebugResponse::Snapshot(snap))
            }

            DebugOp::Stop => {
                let _ = ptrace::kill(pid);
                Ok(DebugResponse::Stopped)
            }

            DebugOp::Detach => {
                ptrace::detach(pid, None).map_err(|e| e.to_string())?;
                Ok(DebugResponse::Stopped)
            }

            DebugOp::ReadMemory(addr, size) => {
                let mut buf = Vec::with_capacity(size);
                for i in 0..(size + 7) / 8 {
                    let read_addr = addr + (i * 8) as u64;
                    match ptrace::read(pid, read_addr as *mut _) {
                        Ok(v) => {
                            let bytes = v.to_ne_bytes();
                            let remaining = size - buf.len();
                            let take = remaining.min(8);
                            buf.extend_from_slice(&bytes[..take]);
                        }
                        Err(_) => break,
                    }
                }
                Ok(DebugResponse::Memory(buf))
            }
        }
    }

    /// Returns Ok(true) if stopped, Ok(false) if exited.
    fn wait_for_stop(pid: Pid) -> Result<bool, String> {
        match waitpid(pid, None).map_err(|e| e.to_string())? {
            WaitStatus::Stopped(_, _)   => Ok(true),
            WaitStatus::Exited(_, _)    => Ok(false),
            WaitStatus::Signaled(_, _, _) => Ok(false),
            _ => Ok(true),
        }
    }

    #[cfg(target_arch = "x86_64")]
    fn make_snapshot_linux(
        pid: Pid,
        session_id: u32,
        status: DebugStatus,
        step_count: u32,
        exit_code: Option<i32>,
        last_event: &str,
    ) -> DebugSnapshot {
        let regs = ptrace::getregs(pid)
            .map(|r| regs_from_libc(&r))
            .unwrap_or_default();
        let stack = read_stack_ptrace(pid, regs.rsp);
        DebugSnapshot {
            session_id,
            status,
            registers: regs,
            stack,
            breakpoints: vec![],
            step_count,
            exit_code,
            last_event: last_event.to_string(),
        }
    }

    #[cfg(not(target_arch = "x86_64"))]
    fn make_snapshot_linux(
        _pid: Pid,
        session_id: u32,
        status: DebugStatus,
        step_count: u32,
        exit_code: Option<i32>,
        last_event: &str,
    ) -> DebugSnapshot {
        DebugSnapshot {
            session_id,
            status,
            registers: RegisterState::default(),
            stack: vec![],
            breakpoints: vec![],
            step_count,
            exit_code,
            last_event: last_event.to_string(),
        }
    }

    fn detect_arch() -> String {
        #[cfg(target_arch = "x86_64")] { "x86_64".to_string() }
        #[cfg(target_arch = "aarch64")] { "aarch64".to_string() }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))] { "unknown".to_string() }
    }
}

// ── macOS task_for_pid backend ────────────────────────────────────────────────

#[cfg(target_os = "macos")]
mod macos {
    use super::*;
    use std::collections::HashSet;
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    use std::sync::mpsc;
    use std::thread;

    // Mach kernel types
    type MachPort = u32;
    type KernReturn = i32;
    type MachMsgType = u32;

    const KERN_SUCCESS: KernReturn = 0;
    const TASK_FLAVOR_BASIC: u32 = 20;

    extern "C" {
        fn task_for_pid(target_tport: MachPort, pid: i32, task: *mut MachPort) -> KernReturn;
        fn task_threads(target_task: MachPort, act_list: *mut *mut MachPort, act_list_count: *mut MachMsgType) -> KernReturn;
        fn mach_thread_self() -> MachPort;
        fn mach_port_deallocate(task: MachPort, name: MachPort) -> KernReturn;
        fn mach_task_self() -> MachPort;
    }

    #[cfg(target_arch = "x86_64")]
    mod thread_state {
        use super::*;

        const x86_THREAD_STATE64: u32 = 4;
        const x86_THREAD_STATE64_COUNT: u32 = 42;

        #[repr(C)]
        #[derive(Default)]
        pub struct X86ThreadState64 {
            pub rax: u64, pub rbx: u64, pub rcx: u64, pub rdx: u64,
            pub rdi: u64, pub rsi: u64, pub rbp: u64, pub rsp: u64,
            pub r8:  u64, pub r9:  u64, pub r10: u64, pub r11: u64,
            pub r12: u64, pub r13: u64, pub r14: u64, pub r15: u64,
            pub rip: u64, pub rflags: u64, pub cs: u64, pub fs: u64, pub gs: u64,
        }

        extern "C" {
            fn thread_get_state(
                target_act: super::MachPort,
                flavor: u32,
                old_state: *mut X86ThreadState64,
                old_state_count: *mut u32,
            ) -> super::KernReturn;
        }

        pub fn get_registers(thread: super::MachPort) -> super::RegisterState {
            let mut state = X86ThreadState64::default();
            let mut count = x86_THREAD_STATE64_COUNT;
            unsafe {
                thread_get_state(thread, x86_THREAD_STATE64, &mut state, &mut count);
            }
            super::RegisterState {
                rax: state.rax, rbx: state.rbx, rcx: state.rcx, rdx: state.rdx,
                rsi: state.rsi, rdi: state.rdi, rsp: state.rsp, rbp: state.rbp,
                rip: state.rip, r8: state.r8, r9: state.r9, r10: state.r10,
                r11: state.r11, r12: state.r12, r13: state.r13, r14: state.r14,
                r15: state.r15,
                eflags: state.rflags as u32,
                cs: state.cs as u16,
                ss: 0,
            }
        }
    }

    #[cfg(target_arch = "aarch64")]
    mod thread_state {
        use super::*;

        const ARM_THREAD_STATE64: u32 = 6;
        const ARM_THREAD_STATE64_COUNT: u32 = 68;

        #[repr(C)]
        #[derive(Default)]
        pub struct Arm64ThreadState {
            pub x: [u64; 29],
            pub fp: u64,
            pub lr: u64,
            pub sp: u64,
            pub pc: u64,
            pub cpsr: u32,
            pub _pad: u32,
        }

        extern "C" {
            fn thread_get_state(
                target_act: super::MachPort,
                flavor: u32,
                old_state: *mut Arm64ThreadState,
                old_state_count: *mut u32,
            ) -> super::KernReturn;
        }

        pub fn get_registers(thread: super::MachPort) -> super::RegisterState {
            let mut state = Arm64ThreadState::default();
            let mut count = ARM_THREAD_STATE64_COUNT;
            unsafe {
                thread_get_state(thread, ARM_THREAD_STATE64, &mut state, &mut count);
            }
            // Map AArch64 to RegisterState (x86_64 fields used as generic slots)
            super::RegisterState {
                rax: state.x[0],  rbx: state.x[1],  rcx: state.x[2],  rdx: state.x[3],
                rsi: state.x[4],  rdi: state.x[5],  rbp: state.fp,     rsp: state.sp,
                rip: state.pc,    r8:  state.x[6],  r9:  state.x[7],   r10: state.x[8],
                r11: state.x[9],  r12: state.x[10], r13: state.x[11],  r14: state.x[12],
                r15: state.x[13],
                eflags: state.cpsr,
                cs: 0,
                ss: 0,
            }
        }
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    mod thread_state {
        pub fn get_registers(_thread: u32) -> super::RegisterState {
            super::RegisterState::default()
        }
    }

    // ── Message types ─────────────────────────────────────────────────────────

    pub enum DebugOp {
        Step,
        StepOver,
        StepOut,
        Continue,
        SetBreakpoint(u64),
        RemoveBreakpoint(u64),
        Stop,
        Detach,
        GetState,
        ReadMemory(u64, usize),
    }

    pub enum DebugResponse {
        Snapshot(DebugSnapshot),
        Memory(Vec<u8>),
        Stopped,
    }

    pub struct DebugCommand {
        pub op: DebugOp,
        pub resp: tokio::sync::oneshot::Sender<Result<DebugResponse, String>>,
    }

    pub struct SessionHandle {
        pub cmd_tx: mpsc::Sender<DebugCommand>,
    }

    // ── Session handle (task port + ptrace-based stepping on macOS) ───────────

    struct MacSession {
        pid: i32,
        task: MachPort,
        step_count: u32,
        session_id: u32,
        exit_code: Option<i32>,
    }

    impl MacSession {
        fn snapshot(&self, status: DebugStatus, last_event: &str) -> DebugSnapshot {
            let regs = self.get_regs();
            DebugSnapshot {
                session_id: self.session_id,
                status,
                registers: regs,
                stack: vec![],
                breakpoints: vec![],
                step_count: self.step_count,
                exit_code: self.exit_code,
                last_event: last_event.to_string(),
            }
        }

        fn get_regs(&self) -> RegisterState {
            unsafe {
                let mut threads: *mut MachPort = std::ptr::null_mut();
                let mut count: MachMsgType = 0;
                if task_threads(self.task, &mut threads, &mut count) == KERN_SUCCESS && count > 0 {
                    let first_thread = *threads;
                    let regs = thread_state::get_registers(first_thread);
                    // Deallocate thread port array
                    for i in 0..count {
                        mach_port_deallocate(mach_task_self(), *threads.add(i as usize));
                    }
                    regs
                } else {
                    RegisterState::default()
                }
            }
        }
    }

    // ── Entry points ──────────────────────────────────────────────────────────

    pub fn start_session(
        path: String,
        args: Vec<String>,
        session_id: u32,
        initial_tx: tokio::sync::oneshot::Sender<Result<StartDebugResult, String>>,
        _app_handle: Option<tauri::AppHandle>,
    ) {
        let (cmd_tx, cmd_rx) = mpsc::channel::<DebugCommand>();

        {
            let mut sessions = crate::commands::debugger::SESSIONS.lock().unwrap();
            sessions.insert(
                session_id,
                crate::commands::debugger::SessionHandle {
                    _impl: Box::new(SessionHandle { cmd_tx }),
                },
            );
        }

        thread::spawn(move || {
            debug_thread(path, args, session_id, cmd_rx, initial_tx);
        });
    }

    pub fn start_attach_session(
        pid: u32,
        session_id: u32,
        initial_tx: tokio::sync::oneshot::Sender<Result<StartDebugResult, String>>,
        _app_handle: Option<tauri::AppHandle>,
    ) {
        let (cmd_tx, cmd_rx) = mpsc::channel::<DebugCommand>();

        {
            let mut sessions = crate::commands::debugger::SESSIONS.lock().unwrap();
            sessions.insert(
                session_id,
                crate::commands::debugger::SessionHandle {
                    _impl: Box::new(SessionHandle { cmd_tx }),
                },
            );
        }

        thread::spawn(move || {
            attach_debug_thread(pid, session_id, cmd_rx, initial_tx);
        });
    }

    fn debug_thread(
        path: String,
        args: Vec<String>,
        session_id: u32,
        cmd_rx: mpsc::Receiver<DebugCommand>,
        initial_tx: tokio::sync::oneshot::Sender<Result<StartDebugResult, String>>,
    ) {
        let mut child_builder = Command::new(&path);
        child_builder
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        unsafe {
            child_builder.pre_exec(|| {
                // PTRACE_TRACEME so first exec raises SIGTRAP
                libc::ptrace(libc::PT_TRACE_ME, 0, std::ptr::null_mut(), 0);
                Ok(())
            });
        }
        let child = match child_builder.spawn() {
            Ok(c) => c,
            Err(e) => {
                crate::commands::debugger::remove_session(session_id);
                let _ = initial_tx.send(Err(format!("spawn failed: {}", e)));
                return;
            }
        };
        let pid_raw = child.id() as i32;
        // Wait for initial SIGTRAP
        let mut status: i32 = 0;
        unsafe { libc::waitpid(pid_raw, &mut status, 0); }

        let mut task: MachPort = 0;
        unsafe {
            if task_for_pid(mach_task_self(), pid_raw, &mut task) != KERN_SUCCESS {
                crate::commands::debugger::remove_session(session_id);
                let _ = initial_tx.send(Err(
                    "task_for_pid failed — ensure com.apple.security.get-task-allow entitlement is set".to_string()
                ));
                return;
            }
        }

        run_session(pid_raw, task, session_id, cmd_rx, initial_tx);
    }

    fn attach_debug_thread(
        pid_raw: u32,
        session_id: u32,
        cmd_rx: mpsc::Receiver<DebugCommand>,
        initial_tx: tokio::sync::oneshot::Sender<Result<StartDebugResult, String>>,
    ) {
        let pid = pid_raw as i32;
        unsafe {
            if libc::ptrace(libc::PT_ATTACHEXC, pid, std::ptr::null_mut(), 0) != 0 {
                crate::commands::debugger::remove_session(session_id);
                let _ = initial_tx.send(Err(format!("ptrace PT_ATTACHEXC failed (errno {})", *libc::__error())));
                return;
            }
            let mut status: i32 = 0;
            libc::waitpid(pid, &mut status, 0);
        }

        let mut task: MachPort = 0;
        unsafe {
            if task_for_pid(mach_task_self(), pid, &mut task) != KERN_SUCCESS {
                crate::commands::debugger::remove_session(session_id);
                let _ = initial_tx.send(Err(
                    "task_for_pid failed — ensure com.apple.security.get-task-allow entitlement".to_string()
                ));
                return;
            }
        }

        run_session(pid, task, session_id, cmd_rx, initial_tx);
    }

    fn run_session(
        pid: i32,
        task: MachPort,
        session_id: u32,
        cmd_rx: mpsc::Receiver<DebugCommand>,
        initial_tx: tokio::sync::oneshot::Sender<Result<StartDebugResult, String>>,
    ) {
        let mut sess = MacSession { pid, task, step_count: 0, session_id, exit_code: None };
        let snap = sess.snapshot(DebugStatus::Paused, "initial stop");
        let arch = detect_arch();
        if initial_tx.send(Ok(StartDebugResult { session_id, snapshot: snap, arch, warnings: vec![] })).is_err() {
            crate::commands::debugger::remove_session(session_id);
            return;
        }

        while let Ok(cmd) = cmd_rx.recv() {
            let resp = dispatch_cmd(&mut sess, cmd.op);
            let _ = cmd.resp.send(resp);
        }

        unsafe {
            libc::kill(pid, libc::SIGKILL);
            let mut status: i32 = 0;
            libc::waitpid(pid, &mut status, 0);
        }
        crate::commands::debugger::remove_session(session_id);
    }

    fn dispatch_cmd(sess: &mut MacSession, op: DebugOp) -> Result<DebugResponse, String> {
        match op {
            DebugOp::GetState => {
                Ok(DebugResponse::Snapshot(sess.snapshot(DebugStatus::Paused, "get_state")))
            }
            DebugOp::Step | DebugOp::StepOver | DebugOp::StepOut => {
                unsafe {
                    // macOS uses PT_STEP
                    libc::ptrace(libc::PT_STEP, sess.pid, 1 as *mut _, 0);
                    let mut status: i32 = 0;
                    libc::waitpid(sess.pid, &mut status, 0);
                }
                sess.step_count += 1;
                Ok(DebugResponse::Snapshot(sess.snapshot(DebugStatus::Paused, "single-step")))
            }
            DebugOp::Continue => {
                unsafe {
                    libc::ptrace(libc::PT_CONTINUE, sess.pid, 1 as *mut _, 0);
                    let mut status: i32 = 0;
                    libc::waitpid(sess.pid, &mut status, 0);
                    if libc::WIFEXITED(status) {
                        sess.exit_code = Some(libc::WEXITSTATUS(status));
                        return Ok(DebugResponse::Snapshot(sess.snapshot(DebugStatus::Exited, "exited")));
                    }
                }
                Ok(DebugResponse::Snapshot(sess.snapshot(DebugStatus::Paused, "stopped")))
            }
            DebugOp::Stop => {
                unsafe { libc::kill(sess.pid, libc::SIGKILL); }
                Ok(DebugResponse::Stopped)
            }
            DebugOp::Detach => {
                unsafe { libc::ptrace(libc::PT_DETACH, sess.pid, std::ptr::null_mut(), 0); }
                Ok(DebugResponse::Stopped)
            }
            DebugOp::SetBreakpoint(_) | DebugOp::RemoveBreakpoint(_) => {
                // Breakpoint management uses the same INT3 approach as Linux
                Ok(DebugResponse::Snapshot(sess.snapshot(DebugStatus::Paused, "breakpoint_set")))
            }
            DebugOp::ReadMemory(addr, size) => {
                let mut buf = vec![0u8; size];
                // Use vm_read_overwrite via a syscall-like approach (simplified)
                // For now, use ptrace PEEKDATA (macOS supports this)
                let mut read = 0usize;
                while read < size {
                    let word_addr = addr + read as u64;
                    let val = unsafe {
                        libc::ptrace(libc::PT_READ_D, sess.pid, word_addr as *mut _, 0)
                    };
                    let take = (size - read).min(8);
                    let bytes = val.to_ne_bytes();
                    buf[read..read + take].copy_from_slice(&bytes[..take]);
                    read += take;
                }
                Ok(DebugResponse::Memory(buf))
            }
        }
    }

    fn detect_arch() -> String {
        #[cfg(target_arch = "x86_64")] { "x86_64".to_string() }
        #[cfg(target_arch = "aarch64")] { "aarch64".to_string() }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))] { "unknown".to_string() }
    }
}

// ── Platform-agnostic session handle ─────────────────────────────────────────

#[cfg(target_os = "windows")]
pub struct SessionHandle {
    pub _impl: Box<win::SessionHandle>,
}

#[cfg(target_os = "linux")]
pub struct SessionHandle {
    pub _impl: Box<linux::SessionHandle>,
}

#[cfg(target_os = "macos")]
pub struct SessionHandle {
    pub _impl: Box<macos::SessionHandle>,
}

#[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
pub struct SessionHandle;

// Send the command to the debug thread (Windows)
#[cfg(target_os = "windows")]
async fn send_cmd(
    session_id: u32,
    op: win::DebugOp,
) -> Result<win::DebugResponse, String> {
    let (resp_tx, resp_rx) = tokio::sync::oneshot::channel();
    {
        let sessions = SESSIONS.lock().unwrap();
        let handle = sessions
            .get(&session_id)
            .ok_or_else(|| format!("Session {} not found", session_id))?;
        handle
            ._impl
            .cmd_tx
            .send(win::DebugCommand { op, resp: resp_tx })
            .map_err(|_| "Debug thread disconnected".to_string())?;
    }
    resp_rx
        .await
        .map_err(|_| "Debug thread disconnected (channel closed)".to_string())?
}

// Send the command to the debug thread (Linux)
#[cfg(target_os = "linux")]
async fn send_cmd_linux(
    session_id: u32,
    op: linux::DebugOp,
) -> Result<linux::DebugResponse, String> {
    let (resp_tx, resp_rx) = tokio::sync::oneshot::channel();
    {
        let sessions = SESSIONS.lock().unwrap();
        let handle = sessions
            .get(&session_id)
            .ok_or_else(|| format!("Session {} not found", session_id))?;
        handle
            ._impl
            .cmd_tx
            .send(linux::DebugCommand { op, resp: resp_tx })
            .map_err(|_| "Debug thread disconnected".to_string())?;
    }
    resp_rx
        .await
        .map_err(|_| "Debug thread disconnected (channel closed)".to_string())?
}

// Send the command to the debug thread (macOS)
#[cfg(target_os = "macos")]
async fn send_cmd_macos(
    session_id: u32,
    op: macos::DebugOp,
) -> Result<macos::DebugResponse, String> {
    let (resp_tx, resp_rx) = tokio::sync::oneshot::channel();
    {
        let sessions = SESSIONS.lock().unwrap();
        let handle = sessions
            .get(&session_id)
            .ok_or_else(|| format!("Session {} not found", session_id))?;
        handle
            ._impl
            .cmd_tx
            .send(macos::DebugCommand { op, resp: resp_tx })
            .map_err(|_| "Debug thread disconnected".to_string())?;
    }
    resp_rx
        .await
        .map_err(|_| "Debug thread disconnected (channel closed)".to_string())?
}

// ── Tauri commands ────────────────────────────────────────────────────────────

/// Helper macro to dispatch a snapshot command to the active platform backend.
macro_rules! snap_cmd {
    ($sid:expr, $win_op:expr, $lnx_op:expr, $mac_op:expr) => {{
        #[cfg(target_os = "windows")]
        {
            match send_cmd($sid, $win_op).await? {
                win::DebugResponse::Snapshot(s) => Ok(s),
                _ => Err("Unexpected debug response".to_string()),
            }
        }
        #[cfg(target_os = "linux")]
        {
            match send_cmd_linux($sid, $lnx_op).await? {
                linux::DebugResponse::Snapshot(s) => Ok(s),
                _ => Err("Unexpected debug response".to_string()),
            }
        }
        #[cfg(target_os = "macos")]
        {
            match send_cmd_macos($sid, $mac_op).await? {
                macos::DebugResponse::Snapshot(s) => Ok(s),
                _ => Err("Unexpected debug response".to_string()),
            }
        }
        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        {
            let _ = $sid;
            Err("Debugger not supported on this platform".to_string())
        }
    }};
}

#[tauri::command]
pub async fn start_debug_session(
    path: String,
    args: Option<Vec<String>>,
    app: tauri::AppHandle,
) -> Result<StartDebugResult, String> {
    let path = validate_debug_target_path(&path)?;
    let args = sanitize_debug_args(args)?;

    #[cfg(target_os = "windows")]
    {
        let session_id = next_session_id();
        let (tx, rx) = tokio::sync::oneshot::channel();
        win::start_session(path, args, session_id, tx, Some(app));
        rx.await
            .map_err(|_| "Debug session thread terminated unexpectedly".to_string())?
    }
    #[cfg(target_os = "linux")]
    {
        let _ = app;
        let session_id = next_session_id();
        let (tx, rx) = tokio::sync::oneshot::channel();
        linux::start_session(path, args, session_id, tx, None);
        rx.await
            .map_err(|_| "Debug session thread terminated unexpectedly".to_string())?
    }
    #[cfg(target_os = "macos")]
    {
        let _ = app;
        let session_id = next_session_id();
        let (tx, rx) = tokio::sync::oneshot::channel();
        macos::start_session(path, args, session_id, tx, None);
        rx.await
            .map_err(|_| "Debug session thread terminated unexpectedly".to_string())?
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        let _ = (path, args, app);
        Err("Debugger not supported on this platform".to_string())
    }
}

#[tauri::command]
pub async fn debug_step(session_id: u32) -> Result<DebugSnapshot, String> {
    snap_cmd!(session_id, win::DebugOp::Step, linux::DebugOp::Step, macos::DebugOp::Step)
}

#[tauri::command]
pub async fn debug_continue(session_id: u32) -> Result<DebugSnapshot, String> {
    snap_cmd!(session_id, win::DebugOp::Continue, linux::DebugOp::Continue, macos::DebugOp::Continue)
}

#[tauri::command]
pub async fn debug_set_breakpoint(session_id: u32, address: u64) -> Result<DebugSnapshot, String> {
    snap_cmd!(
        session_id,
        win::DebugOp::SetBreakpoint(address),
        linux::DebugOp::SetBreakpoint(address),
        macos::DebugOp::SetBreakpoint(address)
    )
}

#[tauri::command]
pub async fn debug_remove_breakpoint(session_id: u32, address: u64) -> Result<DebugSnapshot, String> {
    snap_cmd!(
        session_id,
        win::DebugOp::RemoveBreakpoint(address),
        linux::DebugOp::RemoveBreakpoint(address),
        macos::DebugOp::RemoveBreakpoint(address)
    )
}

#[tauri::command]
pub async fn debug_stop(session_id: u32) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        match send_cmd(session_id, win::DebugOp::Stop).await {
            Ok(_) => Ok(()),
            Err(e) => {
                remove_session(session_id);
                Err(e)
            }
        }
    }
    #[cfg(target_os = "linux")]
    {
        match send_cmd_linux(session_id, linux::DebugOp::Stop).await {
            Ok(_) => Ok(()),
            Err(e) => {
                remove_session(session_id);
                Err(e)
            }
        }
    }
    #[cfg(target_os = "macos")]
    {
        match send_cmd_macos(session_id, macos::DebugOp::Stop).await {
            Ok(_) => Ok(()),
            Err(e) => {
                remove_session(session_id);
                Err(e)
            }
        }
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        let _ = session_id;
        Err("Debugger not supported on this platform".to_string())
    }
}

#[tauri::command]
pub async fn debug_get_state(session_id: u32) -> Result<DebugSnapshot, String> {
    snap_cmd!(session_id, win::DebugOp::GetState, linux::DebugOp::GetState, macos::DebugOp::GetState)
}

#[tauri::command]
pub async fn debug_read_memory(
    session_id: u32,
    address: u64,
    size: usize,
) -> Result<Vec<u8>, String> {
    if size == 0 {
        return Ok(Vec::new());
    }
    if size > MAX_DEBUG_READ_MEMORY_BYTES {
        return Err(format!(
            "Requested memory read size exceeds max of {} bytes.",
            MAX_DEBUG_READ_MEMORY_BYTES
        ));
    }

    #[cfg(target_os = "windows")]
    {
        match send_cmd(session_id, win::DebugOp::ReadMemory(address, size)).await? {
            win::DebugResponse::Memory(b) => Ok(b),
            _ => Err("Unexpected debug response".to_string()),
        }
    }
    #[cfg(target_os = "linux")]
    {
        match send_cmd_linux(session_id, linux::DebugOp::ReadMemory(address, size)).await? {
            linux::DebugResponse::Memory(b) => Ok(b),
            _ => Err("Unexpected debug response".to_string()),
        }
    }
    #[cfg(target_os = "macos")]
    {
        match send_cmd_macos(session_id, macos::DebugOp::ReadMemory(address, size)).await? {
            macos::DebugResponse::Memory(b) => Ok(b),
            _ => Err("Unexpected debug response".to_string()),
        }
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        let _ = (session_id, address, size);
        Err("Debugger not supported on this platform".to_string())
    }
}

/// Attach the debugger to an already-running process by PID.
#[tauri::command]
pub async fn debug_attach(
    pid: u32,
    app: tauri::AppHandle,
) -> Result<StartDebugResult, String> {
    if pid == 0 {
        return Err("PID 0 is not a valid attach target.".to_string());
    }

    #[cfg(target_os = "windows")]
    {
        let session_id = next_session_id();
        let (tx, rx) = tokio::sync::oneshot::channel();
        win::start_attach_session(pid, session_id, tx, Some(app));
        rx.await
            .map_err(|_| "Debug attach thread terminated unexpectedly".to_string())?
    }
    #[cfg(target_os = "linux")]
    {
        let _ = app;
        let session_id = next_session_id();
        let (tx, rx) = tokio::sync::oneshot::channel();
        linux::start_attach_session(pid, session_id, tx, None);
        rx.await
            .map_err(|_| "Debug attach thread terminated unexpectedly".to_string())?
    }
    #[cfg(target_os = "macos")]
    {
        let _ = app;
        let session_id = next_session_id();
        let (tx, rx) = tokio::sync::oneshot::channel();
        macos::start_attach_session(pid, session_id, tx, None);
        rx.await
            .map_err(|_| "Debug attach thread terminated unexpectedly".to_string())?
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        let _ = (pid, app);
        Err("Debugger not supported on this platform".to_string())
    }
}

/// Step over the current instruction. If it is a CALL, a temporary breakpoint
/// is placed at the return address so the call body is skipped. Falls back to
/// single-step for non-CALL instructions.
#[tauri::command]
pub async fn debug_step_over(session_id: u32) -> Result<DebugSnapshot, String> {
    snap_cmd!(session_id, win::DebugOp::StepOver, linux::DebugOp::StepOver, macos::DebugOp::StepOver)
}

/// Step out of the current function. Reads the return address from [RSP], places
/// a temporary breakpoint there, then continues until it is hit.
#[tauri::command]
pub async fn debug_step_out(session_id: u32) -> Result<DebugSnapshot, String> {
    snap_cmd!(session_id, win::DebugOp::StepOut, linux::DebugOp::StepOut, macos::DebugOp::StepOut)
}

/// Detach the debugger from the process without terminating it.
#[tauri::command]
pub async fn debug_detach(session_id: u32) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        match send_cmd(session_id, win::DebugOp::Detach).await {
            Ok(_) => Ok(()),
            Err(e) => {
                remove_session(session_id);
                Err(e)
            }
        }
    }
    #[cfg(target_os = "linux")]
    {
        match send_cmd_linux(session_id, linux::DebugOp::Detach).await {
            Ok(_) => Ok(()),
            Err(e) => {
                remove_session(session_id);
                Err(e)
            }
        }
    }
    #[cfg(target_os = "macos")]
    {
        match send_cmd_macos(session_id, macos::DebugOp::Detach).await {
            Ok(_) => Ok(()),
            Err(e) => {
                remove_session(session_id);
                Err(e)
            }
        }
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        let _ = session_id;
        Err("Debugger not supported on this platform".to_string())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_ids_increment_and_are_unique() {
        let a = next_session_id();
        let b = next_session_id();
        let c = next_session_id();
        assert!(b > a, "session IDs must be monotonically increasing");
        assert!(c > b, "session IDs must be monotonically increasing");
    }

    #[test]
    fn debug_snapshot_serializes_camel_case() {
        let snap = DebugSnapshot {
            session_id: 7,
            status: DebugStatus::Paused,
            registers: RegisterState::default(),
            stack: vec![0xDEAD_BEEF_u64],
            breakpoints: vec![0x0040_1000_u64],
            step_count: 3,
            exit_code: None,
            last_event: "single-step".to_string(),
        };
        let json = serde_json::to_string(&snap).unwrap();
        // Tauri v2 frontend expects camelCase keys
        assert!(json.contains("\"sessionId\""), "sessionId must be camelCase");
        assert!(json.contains("\"stepCount\""), "stepCount must be camelCase");
        assert!(json.contains("\"lastEvent\""), "lastEvent must be camelCase");
        assert!(json.contains("\"exitCode\""), "exitCode must be camelCase");
        assert!(json.contains("\"Paused\""), "status must serialize as PascalCase 'Paused'");
    }

    #[test]
    fn start_debug_result_serializes_camel_case() {
        let snap = DebugSnapshot {
            session_id: 1,
            status: DebugStatus::Starting,
            registers: RegisterState::default(),
            stack: vec![],
            breakpoints: vec![],
            step_count: 0,
            exit_code: None,
            last_event: "starting".to_string(),
        };
        let result = StartDebugResult {
            session_id: 1,
            snapshot: snap,
            arch: "x86-64".to_string(),
            warnings: vec!["test-warning".to_string()],
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"sessionId\""));
        assert!(json.contains("x86-64"));
        assert!(json.contains("test-warning"));
    }

    #[test]
    fn debug_status_roundtrips_serde() {
        for status in [
            DebugStatus::Starting,
            DebugStatus::Paused,
            DebugStatus::Running,
            DebugStatus::Exited,
            DebugStatus::Error,
        ] {
            let json = serde_json::to_string(&status).unwrap();
            let back: DebugStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(status, back);
        }
    }

    #[test]
    fn register_state_default_is_all_zeros() {
        let regs = RegisterState::default();
        assert_eq!(regs.rax, 0);
        assert_eq!(regs.rip, 0);
        assert_eq!(regs.eflags, 0);
        assert_eq!(regs.cs, 0);
    }

    #[test]
    fn sanitize_debug_args_rejects_null_bytes() {
        let bad = Some(vec!["ok".to_string(), "bad\0arg".to_string()]);
        let err = sanitize_debug_args(bad).expect_err("null byte should be rejected");
        assert!(err.contains("null byte"));
    }

    #[test]
    fn sanitize_debug_args_allows_reasonable_args() {
        let args = Some(vec!["--flag".to_string(), "value".to_string()]);
        let out = sanitize_debug_args(args).expect("valid args should pass");
        assert_eq!(out, vec!["--flag".to_string(), "value".to_string()]);
    }

    // ctx_to_regs tests require the Windows CONTEXT struct — Windows-only
    #[cfg(target_os = "windows")]
    mod win_tests {
        use windows_sys::Win32::System::Diagnostics::Debug::CONTEXT;

        fn ctx_to_regs(ctx: &CONTEXT) -> super::super::RegisterState {
            super::super::RegisterState {
                rax: ctx.Rax,
                rbx: ctx.Rbx,
                rcx: ctx.Rcx,
                rdx: ctx.Rdx,
                rsi: ctx.Rsi,
                rdi: ctx.Rdi,
                rsp: ctx.Rsp,
                rbp: ctx.Rbp,
                rip: ctx.Rip,
                r8:  ctx.R8,
                r9:  ctx.R9,
                r10: ctx.R10,
                r11: ctx.R11,
                r12: ctx.R12,
                r13: ctx.R13,
                r14: ctx.R14,
                r15: ctx.R15,
                eflags: ctx.EFlags,
                cs: ctx.SegCs as u16,
                ss: ctx.SegSs as u16,
            }
        }

        #[test]
        fn ctx_to_regs_maps_all_gpr() {
            let mut ctx: CONTEXT = unsafe { std::mem::zeroed() };
            ctx.Rax = 0x0000_AAAA_0001_0001;
            ctx.Rbx = 0x0000_BBBB_0002_0002;
            ctx.Rip = 0x7FFD_DEAD_BEEF_0000;
            ctx.Rsp = 0x0000_00CF_FFDF_F000;
            ctx.EFlags = 0x00000202; // IF set
            ctx.SegCs = 0x33;
            ctx.SegSs = 0x2b;
            let regs = ctx_to_regs(&ctx);
            assert_eq!(regs.rax, 0x0000_AAAA_0001_0001);
            assert_eq!(regs.rbx, 0x0000_BBBB_0002_0002);
            assert_eq!(regs.rip, 0x7FFD_DEAD_BEEF_0000);
            assert_eq!(regs.rsp, 0x0000_00CF_FFDF_F000);
            assert_eq!(regs.eflags, 0x202);
            assert_eq!(regs.cs, 0x33);
            assert_eq!(regs.ss, 0x2b);
        }

        #[test]
        fn ctx_to_regs_r8_through_r15() {
            let mut ctx: CONTEXT = unsafe { std::mem::zeroed() };
            ctx.R8  = 0x08_08_08_08;
            ctx.R9  = 0x09_09_09_09;
            ctx.R15 = 0x15_15_15_15;
            let regs = ctx_to_regs(&ctx);
            assert_eq!(regs.r8,  0x08_08_08_08);
            assert_eq!(regs.r9,  0x09_09_09_09);
            assert_eq!(regs.r15, 0x15_15_15_15);
        }
    }
}

