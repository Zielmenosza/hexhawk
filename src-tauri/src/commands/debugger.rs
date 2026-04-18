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

fn next_session_id() -> u32 {
    let mut c = SESSION_COUNTER.lock().unwrap();
    *c += 1;
    *c
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
        ContinueDebugEvent, FlushInstructionCache, GetThreadContext, ReadProcessMemory,
        SetThreadContext, WaitForDebugEvent, WriteProcessMemory, CONTEXT,
        CREATE_PROCESS_DEBUG_EVENT, DEBUG_EVENT, EXCEPTION_DEBUG_EVENT,
        EXIT_PROCESS_DEBUG_EVENT, LOAD_DLL_DEBUG_EVENT, OUTPUT_DEBUG_STRING_EVENT,
    };
    use windows_sys::Win32::System::Threading::{
        CreateProcessW, TerminateProcess, CREATE_NEW_CONSOLE, DEBUG_PROCESS,
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
        Continue,
        SetBreakpoint(u64),
        RemoveBreakpoint(u64),
        Stop,
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
            debug_thread(path, session_id, cmd_rx, initial_tx);
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

    // ── Debug thread ──────────────────────────────────────────────────────────

    fn debug_thread(
        path: String,
        session_id: u32,
        cmd_rx: mpsc::Receiver<DebugCommand>,
        initial_tx: tokio::sync::oneshot::Sender<Result<StartDebugResult, String>>,
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
            let _ = initial_tx.send(Err(err));
            return;
        }

        let process = pi.hProcess;
        let mut main_thread = pi.hThread;
        let _pid = pi.dwProcessId;

        // Thread handle map: tid → handle
        let mut thread_handles: HashMap<u32, HANDLE> = HashMap::new();
        thread_handles.insert(pi.dwThreadId, main_thread);

        // Breakpoints: addr → original byte
        let mut bp_originals: HashMap<u64, u8> = HashMap::new();
        // User-requested breakpoints
        let mut user_bps: std::collections::HashSet<u64> = std::collections::HashSet::new();

        let mut step_count = 0u32;
        let mut exit_code: Option<i32> = None;
        let mut system_bp_hit = false; // First EXCEPTION_BREAKPOINT from loader

        // ── Initial debug event loop until first system breakpoint ────────────
        let (initial_ctx, init_pending_pid, init_pending_tid) = loop {
            let mut evt: DEBUG_EVENT = unsafe { std::mem::zeroed() };
            let ok = unsafe { WaitForDebugEvent(&mut evt, 5000) };
            if ok == FALSE {
                let _ = initial_tx.send(Err("Timed out waiting for process start".to_string()));
                unsafe { TerminateProcess(process, 1); }
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
                        // System breakpoint: stop here
                        system_bp_hit = true;
                        let thread = thread_handles.get(&evt.dwThreadId).copied().unwrap_or(main_thread);
                        if let Some(ctx) = unsafe { get_ctx(thread) } {
                            break (ctx, evt.dwProcessId, evt.dwThreadId);
                        }
                        // If we can't get context, continue
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
            session_id,
            DebugStatus::Paused,
            &initial_ctx,
            process,
            &bp_list,
            0,
            None,
            "system-breakpoint",
        );
        let _ = initial_tx.send(Ok(StartDebugResult {
            session_id,
            snapshot: initial_snapshot,
            arch: "x86-64".to_string(),
            warnings: vec![],
        }));

        // Current paused state
        let mut current_ctx = initial_ctx;
        let mut current_thread = main_thread;
        let mut status = DebugStatus::Paused;
        let mut last_event_str = "system-breakpoint".to_string();
        // Track the process/thread IDs of the last unconfirmed debug event.
        // ContinueDebugEvent MUST be called with these exact IDs before the next op.
        let mut pending_event_pid: u32 = init_pending_pid;
        let mut pending_event_tid: u32 = init_pending_tid;

        // ── Command loop ──────────────────────────────────────────────────────

        // Helper: wait for the next relevant event (step or breakpoint hit)
        // Returns (new context, new status, event description) or error
        let wait_for_stop = |process: HANDLE,
                             thread_handles: &HashMap<u32, HANDLE>,
                             main_thread: HANDLE,
                             bp_originals: &mut HashMap<u64, u8>,
                             user_bps: &std::collections::HashSet<u64>,
                             step_count: &mut u32,
                             exit_code: &mut Option<i32>,
                             pending_pid: &mut u32,
                             pending_tid: &mut u32|
         -> Result<(CONTEXT, HANDLE, DebugStatus, String), String> {
            let timeout_ms = 10_000u32;
            loop {
                let mut evt: DEBUG_EVENT = unsafe { std::mem::zeroed() };
                let ok = unsafe { WaitForDebugEvent(&mut evt, timeout_ms) };
                if ok == FALSE {
                    return Err("WaitForDebugEvent timed out (10s)".to_string());
                }
                let tid = evt.dwThreadId;
                let thread = thread_handles.get(&tid).copied().unwrap_or(main_thread);

                match evt.dwDebugEventCode {
                    EXCEPTION_DEBUG_EVENT => {
                        let exc = unsafe { &evt.u.Exception.ExceptionRecord };
                        let code = exc.ExceptionCode;
                        let addr = exc.ExceptionAddress as u64;

                        if code == EXCEPTION_SINGLE_STEP {
                            *step_count += 1;
                            let ctx = unsafe { get_ctx(thread) }
                                .ok_or_else(|| "GetThreadContext failed".to_string())?;
                            // Save pending event IDs — caller calls ContinueDebugEvent before next op.
                            *pending_pid = evt.dwProcessId;
                            *pending_tid = tid;
                            return Ok((ctx, thread, DebugStatus::Paused, "single-step".to_string()));
                        } else if code == EXCEPTION_BREAKPOINT {
                            // Restore original byte and rewind RIP
                            if let Some(orig) = bp_originals.remove(&addr) {
                                unsafe { write_byte(process, addr, orig); }
                                // Rewind RIP by 1 (INT3 is 1 byte)
                                if let Some(mut ctx) = unsafe { get_ctx(thread) } {
                                    ctx.Rip -= 1;
                                    unsafe { set_ctx(thread, &ctx); }
                                    // Preserve orig byte so re-set_breakpoint can re-arm
                                    if user_bps.contains(&addr) {
                                        bp_originals.insert(addr, orig);
                                    }
                                    // Save pending event IDs — caller calls ContinueDebugEvent
                                    *pending_pid = evt.dwProcessId;
                                    *pending_tid = tid;
                                    return Ok((ctx, thread, DebugStatus::Paused, format!("breakpoint@{:#x}", addr)));
                                }
                            }
                            // Unknown/system breakpoint — just continue
                            unsafe { ContinueDebugEvent(evt.dwProcessId, tid, DBG_CONTINUE); }
                        } else {
                            unsafe {
                                ContinueDebugEvent(evt.dwProcessId, tid, DBG_EXCEPTION_NOT_HANDLED);
                            }
                        }
                    }
                    EXIT_PROCESS_DEBUG_EVENT => {
                        let info = unsafe { &evt.u.ExitProcess };
                        *exit_code = Some(info.dwExitCode as i32);
                        let ctx: CONTEXT = unsafe { std::mem::zeroed() };
                        unsafe {
                            ContinueDebugEvent(evt.dwProcessId, tid, DBG_CONTINUE);
                        }
                        return Ok((ctx, thread, DebugStatus::Exited, "exited".to_string()));
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
                    _ => {
                        unsafe { ContinueDebugEvent(evt.dwProcessId, tid, DBG_CONTINUE); }
                    }
                }
            }
        };

        // Command dispatch loop
        while let Ok(cmd) = cmd_rx.recv() {
            let bp_list: Vec<u64> = user_bps.iter().copied().collect();

            match cmd.op {
                DebugOp::GetState => {
                    let snap = make_snapshot(
                        session_id,
                        status.clone(),
                        &current_ctx,
                        process,
                        &bp_list,
                        step_count,
                        exit_code,
                        &last_event_str,
                    );
                    let _ = cmd.resp.send(Ok(DebugResponse::Snapshot(snap)));
                }

                DebugOp::Step => {
                    if status == DebugStatus::Exited {
                        let snap = make_snapshot(
                            session_id, DebugStatus::Exited, &current_ctx,
                            process, &bp_list, step_count, exit_code, "exited",
                        );
                        let _ = cmd.resp.send(Ok(DebugResponse::Snapshot(snap)));
                        continue;
                    }
                    // Set trap flag
                    let mut ctx = current_ctx;
                    ctx.EFlags |= 0x100; // TF
                    unsafe { set_ctx(current_thread, &ctx); }
                    // Resume from the last pending debug event
                    unsafe { ContinueDebugEvent(pending_event_pid, pending_event_tid, DBG_CONTINUE); }
                    match wait_for_stop(
                        process, &thread_handles, main_thread,
                        &mut bp_originals, &user_bps,
                        &mut step_count, &mut exit_code,
                        &mut pending_event_pid, &mut pending_event_tid,
                    ) {
                        Ok((ctx, thread, new_status, event)) => {
                            current_ctx = ctx;
                            current_thread = thread;
                            status = new_status;
                            last_event_str = event;
                            let bp_list2: Vec<u64> = user_bps.iter().copied().collect();
                            let snap = make_snapshot(
                                session_id, status.clone(), &current_ctx,
                                process, &bp_list2, step_count, exit_code, &last_event_str,
                            );
                            let _ = cmd.resp.send(Ok(DebugResponse::Snapshot(snap)));
                        }
                        Err(e) => {
                            let _ = cmd.resp.send(Err(e));
                        }
                    }
                }

                DebugOp::Continue => {
                    if status == DebugStatus::Exited {
                        let snap = make_snapshot(
                            session_id, DebugStatus::Exited, &current_ctx,
                            process, &bp_list, step_count, exit_code, "exited",
                        );
                        let _ = cmd.resp.send(Ok(DebugResponse::Snapshot(snap)));
                        continue;
                    }
                    // Resume from the last pending debug event
                    unsafe { ContinueDebugEvent(pending_event_pid, pending_event_tid, DBG_CONTINUE); }
                    match wait_for_stop(
                        process, &thread_handles, main_thread,
                        &mut bp_originals, &user_bps,
                        &mut step_count, &mut exit_code,
                        &mut pending_event_pid, &mut pending_event_tid,
                    ) {
                        Ok((ctx, thread, new_status, event)) => {
                            current_ctx = ctx;
                            current_thread = thread;
                            status = new_status;
                            last_event_str = event;
                            let bp_list2: Vec<u64> = user_bps.iter().copied().collect();
                            let snap = make_snapshot(
                                session_id, status.clone(), &current_ctx,
                                process, &bp_list2, step_count, exit_code, &last_event_str,
                            );
                            let _ = cmd.resp.send(Ok(DebugResponse::Snapshot(snap)));
                        }
                        Err(e) => { let _ = cmd.resp.send(Err(e)); }
                    }
                }

                DebugOp::SetBreakpoint(addr) => {
                    user_bps.insert(addr);
                    if let Some(orig) = unsafe { read_byte(process, addr) } {
                        bp_originals.insert(addr, orig);
                        unsafe { write_byte(process, addr, 0xCC); }
                    }
                    let bp_list2: Vec<u64> = user_bps.iter().copied().collect();
                    let snap = make_snapshot(
                        session_id, status.clone(), &current_ctx,
                        process, &bp_list2, step_count, exit_code, &last_event_str,
                    );
                    let _ = cmd.resp.send(Ok(DebugResponse::Snapshot(snap)));
                }

                DebugOp::RemoveBreakpoint(addr) => {
                    user_bps.remove(&addr);
                    if let Some(orig) = bp_originals.remove(&addr) {
                        unsafe { write_byte(process, addr, orig); }
                    }
                    let bp_list2: Vec<u64> = user_bps.iter().copied().collect();
                    let snap = make_snapshot(
                        session_id, status.clone(), &current_ctx,
                        process, &bp_list2, step_count, exit_code, &last_event_str,
                    );
                    let _ = cmd.resp.send(Ok(DebugResponse::Snapshot(snap)));
                }

                DebugOp::ReadMemory(addr, size) => {
                    let clamped = size.min(4096);
                    let mut buf = vec![0u8; clamped];
                    let mut read = 0usize;
                    let ok = unsafe {
                        ReadProcessMemory(
                            process,
                            addr as *const _,
                            buf.as_mut_ptr() as *mut _,
                            clamped,
                            &mut read,
                        )
                    };
                    if ok != FALSE {
                        buf.truncate(read);
                        let _ = cmd.resp.send(Ok(DebugResponse::Memory(buf)));
                    } else {
                        let _ = cmd.resp.send(Err(format!("ReadProcessMemory failed at {:#x}", addr)));
                    }
                }

                DebugOp::Stop => {
                    unsafe { TerminateProcess(process, 0); }
                    unsafe { CloseHandle(process); }
                    // Remove from session registry
                    let mut sessions = crate::commands::debugger::SESSIONS.lock().unwrap();
                    sessions.remove(&session_id);
                    let _ = cmd.resp.send(Ok(DebugResponse::Stopped));
                    return;
                }
            }
        }

        // cmd_rx dropped — clean up
        unsafe { TerminateProcess(process, 0); }
        unsafe { CloseHandle(process); }
    }
}

// ── Platform-agnostic session handle ─────────────────────────────────────────

#[cfg(target_os = "windows")]
pub struct SessionHandle {
    pub _impl: Box<win::SessionHandle>,
}

#[cfg(not(target_os = "windows"))]
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

// ── Tauri commands ────────────────────────────────────────────────────────────

#[tauri::command]
pub async fn start_debug_session(
    path: String,
    args: Option<Vec<String>>,
) -> Result<StartDebugResult, String> {
    #[cfg(target_os = "windows")]
    {
        let session_id = next_session_id();
        let (tx, rx) = tokio::sync::oneshot::channel();
        win::start_session(path, args.unwrap_or_default(), session_id, tx);
        rx.await
            .map_err(|_| "Debug session thread terminated unexpectedly".to_string())?
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (path, args);
        Err("Debugger is only supported on Windows".to_string())
    }
}

#[tauri::command]
pub async fn debug_step(session_id: u32) -> Result<DebugSnapshot, String> {
    #[cfg(target_os = "windows")]
    {
        match send_cmd(session_id, win::DebugOp::Step).await? {
            win::DebugResponse::Snapshot(s) => Ok(s),
            _ => Err("Unexpected debug response".to_string()),
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = session_id;
        Err("Debugger is only supported on Windows".to_string())
    }
}

#[tauri::command]
pub async fn debug_continue(session_id: u32) -> Result<DebugSnapshot, String> {
    #[cfg(target_os = "windows")]
    {
        match send_cmd(session_id, win::DebugOp::Continue).await? {
            win::DebugResponse::Snapshot(s) => Ok(s),
            _ => Err("Unexpected debug response".to_string()),
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = session_id;
        Err("Debugger is only supported on Windows".to_string())
    }
}

#[tauri::command]
pub async fn debug_set_breakpoint(session_id: u32, address: u64) -> Result<DebugSnapshot, String> {
    #[cfg(target_os = "windows")]
    {
        match send_cmd(session_id, win::DebugOp::SetBreakpoint(address)).await? {
            win::DebugResponse::Snapshot(s) => Ok(s),
            _ => Err("Unexpected debug response".to_string()),
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (session_id, address);
        Err("Debugger is only supported on Windows".to_string())
    }
}

#[tauri::command]
pub async fn debug_remove_breakpoint(session_id: u32, address: u64) -> Result<DebugSnapshot, String> {
    #[cfg(target_os = "windows")]
    {
        match send_cmd(session_id, win::DebugOp::RemoveBreakpoint(address)).await? {
            win::DebugResponse::Snapshot(s) => Ok(s),
            _ => Err("Unexpected debug response".to_string()),
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (session_id, address);
        Err("Debugger is only supported on Windows".to_string())
    }
}

#[tauri::command]
pub async fn debug_stop(session_id: u32) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        match send_cmd(session_id, win::DebugOp::Stop).await {
            Ok(_) => Ok(()),
            Err(e) => {
                // Session might already be gone — remove it
                let mut sessions = SESSIONS.lock().unwrap();
                sessions.remove(&session_id);
                Err(e)
            }
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = session_id;
        Err("Debugger is only supported on Windows".to_string())
    }
}

#[tauri::command]
pub async fn debug_get_state(session_id: u32) -> Result<DebugSnapshot, String> {
    #[cfg(target_os = "windows")]
    {
        match send_cmd(session_id, win::DebugOp::GetState).await? {
            win::DebugResponse::Snapshot(s) => Ok(s),
            _ => Err("Unexpected debug response".to_string()),
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = session_id;
        Err("Debugger is only supported on Windows".to_string())
    }
}

#[tauri::command]
pub async fn debug_read_memory(
    session_id: u32,
    address: u64,
    size: usize,
) -> Result<Vec<u8>, String> {
    #[cfg(target_os = "windows")]
    {
        match send_cmd(session_id, win::DebugOp::ReadMemory(address, size)).await? {
            win::DebugResponse::Memory(b) => Ok(b),
            _ => Err("Unexpected debug response".to_string()),
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (session_id, address, size);
        Err("Debugger is only supported on Windows".to_string())
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

