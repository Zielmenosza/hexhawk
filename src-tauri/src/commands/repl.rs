use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use once_cell::sync::Lazy;
use rand::distributions::{Alphanumeric, DistString};
use rhai::serde::{from_dynamic, to_dynamic};
use rhai::{Dynamic, Engine, EvalAltResult, Map, Position, Scope};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::commands::script::{classify_entropy, run_step, shannon_entropy, ScriptStep};

static REPL_SESSIONS: Lazy<Mutex<HashMap<String, Arc<Mutex<ReplSessionState>>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

#[derive(Debug, Deserialize)]
pub struct CreateReplSessionRequest {
    pub path: String,
}

#[derive(Debug, Deserialize)]
pub struct ReplEvalRequest {
    pub session_id: String,
    pub code: String,
}

#[derive(Debug, Serialize)]
pub struct ReplSessionInfo {
    pub session_id: String,
    pub path: String,
    pub eval_count: u64,
    pub stored_keys: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ReplEvalResponse {
    pub session_id: String,
    pub path: String,
    pub result: Value,
    pub eval_count: u64,
    pub stored_keys: Vec<String>,
}

#[derive(Debug, Default)]
struct ReplSessionState {
    path: String,
    stored: HashMap<String, Value>,
    eval_count: u64,
}

fn make_session_id() -> String {
    Alphanumeric.sample_string(&mut rand::thread_rng(), 24)
}

fn with_session<T>(session_id: &str, f: impl FnOnce(Arc<Mutex<ReplSessionState>>) -> Result<T, String>) -> Result<T, String> {
    let sessions = REPL_SESSIONS
        .lock()
        .map_err(|_| "REPL session registry is unavailable".to_string())?;
    let session = sessions
        .get(session_id)
        .cloned()
        .ok_or_else(|| format!("Unknown REPL session: {session_id}"))?;
    drop(sessions);
    f(session)
}

fn runtime_error(message: impl Into<String>) -> Box<EvalAltResult> {
    EvalAltResult::ErrorRuntime(message.into().into(), Position::NONE).into()
}

fn json_to_dynamic(value: Value) -> Result<Dynamic, Box<EvalAltResult>> {
    to_dynamic(value).map_err(|e| runtime_error(format!("JSON conversion failed: {e}")))
}

fn dynamic_to_json(value: Dynamic) -> Result<Value, Box<EvalAltResult>> {
    from_dynamic(&value).map_err(|e| runtime_error(format!("Value conversion failed: {e}")))
}

fn call_script_op(path: &str, op: &str, params: Value) -> Result<Value, String> {
    run_step(
        path,
        &ScriptStep {
            op: op.to_string(),
            params,
            result_key: None,
        },
    )
}

fn register_analysis_fns(engine: &mut Engine, session: Arc<Mutex<ReplSessionState>>) {
    let session_for_path = Arc::clone(&session);
    engine.register_fn("path", move || -> String {
        session_for_path
            .lock()
            .map(|state| state.path.clone())
            .unwrap_or_default()
    });

    let session_for_store = Arc::clone(&session);
    engine.register_fn("store", move |key: String, value: Dynamic| -> Result<(), Box<EvalAltResult>> {
        let json = dynamic_to_json(value)?;
        let mut state = session_for_store
            .lock()
            .map_err(|_| runtime_error("REPL session is unavailable"))?;
        state.stored.insert(key, json);
        Ok(())
    });

    let session_for_load = Arc::clone(&session);
    engine.register_fn("load", move |key: String| -> Result<Dynamic, Box<EvalAltResult>> {
        let state = session_for_load
            .lock()
            .map_err(|_| runtime_error("REPL session is unavailable"))?;
        let value = state
            .stored
            .get(&key)
            .cloned()
            .unwrap_or(Value::Null);
        json_to_dynamic(value)
    });

    let session_for_keys = Arc::clone(&session);
    engine.register_fn("keys", move || -> rhai::Array {
        let state = match session_for_keys.lock() {
            Ok(state) => state,
            Err(_) => return rhai::Array::new(),
        };
        let mut keys: Vec<String> = state.stored.keys().cloned().collect();
        keys.sort();
        keys.into_iter().map(Dynamic::from).collect()
    });

    let session_for_run = Arc::clone(&session);
    engine.register_fn("run", move |op: String, params: Map| -> Result<Dynamic, Box<EvalAltResult>> {
        let params_value = dynamic_to_json(Dynamic::from_map(params))?;
        let path = session_for_run
            .lock()
            .map_err(|_| runtime_error("REPL session is unavailable"))?
            .path
            .clone();
        let result = call_script_op(&path, &op, params_value)
            .map_err(runtime_error)?;
        json_to_dynamic(result)
    });

    let session_for_file_size = Arc::clone(&session);
    engine.register_fn("file_size", move || -> Result<i64, Box<EvalAltResult>> {
        let path = session_for_file_size
            .lock()
            .map_err(|_| runtime_error("REPL session is unavailable"))?
            .path
            .clone();
        let value = call_script_op(&path, "file_size", Value::Object(Default::default()))
            .map_err(runtime_error)?;
        value
            .get("bytes")
            .and_then(Value::as_i64)
            .ok_or_else(|| runtime_error("file_size result missing byte count"))
    });

    let session_for_hex = Arc::clone(&session);
    engine.register_fn("hex", move |offset: i64, length: i64| -> Result<String, Box<EvalAltResult>> {
        let path = session_for_hex
            .lock()
            .map_err(|_| runtime_error("REPL session is unavailable"))?
            .path
            .clone();
        let value = call_script_op(
            &path,
            "hex",
            serde_json::json!({
                "offset": offset.max(0) as u64,
                "length": length.max(0) as u64,
            }),
        )
        .map_err(runtime_error)?;
        value
            .get("hex")
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| runtime_error("hex result missing formatted bytes"))
    });

    let session_for_strings = Arc::clone(&session);
    engine.register_fn("strings", move || -> Result<Dynamic, Box<EvalAltResult>> {
        let path = session_for_strings
            .lock()
            .map_err(|_| runtime_error("REPL session is unavailable"))?
            .path
            .clone();
        let value = call_script_op(&path, "strings", Value::Object(Default::default()))
            .map_err(runtime_error)?;
        json_to_dynamic(value)
    });

    let session_for_inspect = Arc::clone(&session);
    engine.register_fn("inspect", move || -> Result<Dynamic, Box<EvalAltResult>> {
        let path = session_for_inspect
            .lock()
            .map_err(|_| runtime_error("REPL session is unavailable"))?
            .path
            .clone();
        let value = call_script_op(&path, "inspect", Value::Object(Default::default()))
            .map_err(runtime_error)?;
        json_to_dynamic(value)
    });

    let session_for_sections = Arc::clone(&session);
    engine.register_fn("section_map", move || -> Result<Dynamic, Box<EvalAltResult>> {
        let path = session_for_sections
            .lock()
            .map_err(|_| runtime_error("REPL session is unavailable"))?
            .path
            .clone();
        let value = call_script_op(&path, "section_map", Value::Object(Default::default()))
            .map_err(runtime_error)?;
        json_to_dynamic(value)
    });

    let session_for_disasm_2 = Arc::clone(&session);
    engine.register_fn("disasm", move |offset: i64, length: i64| -> Result<Dynamic, Box<EvalAltResult>> {
        let path = session_for_disasm_2
            .lock()
            .map_err(|_| runtime_error("REPL session is unavailable"))?
            .path
            .clone();
        let value = call_script_op(
            &path,
            "disassemble",
            serde_json::json!({
                "offset": offset.max(0) as u64,
                "length": length.max(0) as u64,
            }),
        )
        .map_err(runtime_error)?;
        json_to_dynamic(value)
    });

    let session_for_disasm_3 = Arc::clone(&session);
    engine.register_fn(
        "disasm",
        move |offset: i64, length: i64, max_instructions: i64| -> Result<Dynamic, Box<EvalAltResult>> {
            let path = session_for_disasm_3
                .lock()
                .map_err(|_| runtime_error("REPL session is unavailable"))?
                .path
                .clone();
            let value = call_script_op(
                &path,
                "disassemble",
                serde_json::json!({
                    "offset": offset.max(0) as u64,
                    "length": length.max(0) as u64,
                    "max_instructions": max_instructions.max(0) as u64,
                }),
            )
            .map_err(runtime_error)?;
            json_to_dynamic(value)
        },
    );

    let session_for_find = Arc::clone(&session);
    engine.register_fn("find_bytes", move |pattern: String| -> Result<Dynamic, Box<EvalAltResult>> {
        let path = session_for_find
            .lock()
            .map_err(|_| runtime_error("REPL session is unavailable"))?
            .path
            .clone();
        let value = call_script_op(&path, "find_bytes", serde_json::json!({ "pattern": pattern }))
            .map_err(runtime_error)?;
        json_to_dynamic(value)
    });

    let session_for_find_limit = Arc::clone(&session);
    engine.register_fn(
        "find_bytes",
        move |pattern: String, limit: i64| -> Result<Dynamic, Box<EvalAltResult>> {
            let path = session_for_find_limit
                .lock()
                .map_err(|_| runtime_error("REPL session is unavailable"))?
                .path
                .clone();
            let value = call_script_op(
                &path,
                "find_bytes",
                serde_json::json!({
                    "pattern": pattern,
                    "limit": limit.max(0) as u64,
                }),
            )
            .map_err(runtime_error)?;
            json_to_dynamic(value)
        },
    );

    let session_for_xref = Arc::clone(&session);
    engine.register_fn("xref_to", move |address: i64| -> Result<Dynamic, Box<EvalAltResult>> {
        let path = session_for_xref
            .lock()
            .map_err(|_| runtime_error("REPL session is unavailable"))?
            .path
            .clone();
        let value = call_script_op(&path, "xref_to", serde_json::json!({ "address": address.max(0) as u64 }))
            .map_err(runtime_error)?;
        json_to_dynamic(value)
    });

    let session_for_xref_limit = Arc::clone(&session);
    engine.register_fn(
        "xref_to",
        move |address: i64, max_instructions: i64| -> Result<Dynamic, Box<EvalAltResult>> {
            let path = session_for_xref_limit
                .lock()
                .map_err(|_| runtime_error("REPL session is unavailable"))?
                .path
                .clone();
            let value = call_script_op(
                &path,
                "xref_to",
                serde_json::json!({
                    "address": address.max(0) as u64,
                    "max_instructions": max_instructions.max(0) as u64,
                }),
            )
            .map_err(runtime_error)?;
            json_to_dynamic(value)
        },
    );

    let session_for_entropy = Arc::clone(&session);
    engine.register_fn("entropy", move |offset: i64, length: i64| -> Result<Dynamic, Box<EvalAltResult>> {
        let path = session_for_entropy
            .lock()
            .map_err(|_| runtime_error("REPL session is unavailable"))?
            .path
            .clone();
        let bytes = crate::commands::hex::read_hex_range(path, offset.max(0) as u64, length.max(0) as usize)
            .map_err(runtime_error)?;
        json_to_dynamic(serde_json::json!({
            "offset": offset.max(0) as u64,
            "bytes_sampled": bytes.len(),
            "entropy": shannon_entropy(&bytes),
            "interpretation": classify_entropy(shannon_entropy(&bytes)),
        }))
    });
}

fn session_info(session_id: String, state: &ReplSessionState) -> ReplSessionInfo {
    let mut stored_keys: Vec<String> = state.stored.keys().cloned().collect();
    stored_keys.sort();
    ReplSessionInfo {
        session_id,
        path: state.path.clone(),
        eval_count: state.eval_count,
        stored_keys,
    }
}

#[tauri::command]
pub fn create_repl_session(request: CreateReplSessionRequest) -> Result<ReplSessionInfo, String> {
    std::fs::metadata(&request.path)
        .map_err(|_| format!("File not found: {}", request.path))?;

    let session_id = make_session_id();
    let session = Arc::new(Mutex::new(ReplSessionState {
        path: request.path,
        stored: HashMap::new(),
        eval_count: 0,
    }));

    let mut sessions = REPL_SESSIONS
        .lock()
        .map_err(|_| "REPL session registry is unavailable".to_string())?;
    sessions.insert(session_id.clone(), Arc::clone(&session));
    drop(sessions);

    let state = session
        .lock()
        .map_err(|_| "REPL session is unavailable".to_string())?;
    Ok(session_info(session_id, &state))
}

#[tauri::command]
pub fn close_repl_session(session_id: String) -> Result<bool, String> {
    let mut sessions = REPL_SESSIONS
        .lock()
        .map_err(|_| "REPL session registry is unavailable".to_string())?;
    Ok(sessions.remove(&session_id).is_some())
}

#[tauri::command]
pub fn get_repl_session(session_id: String) -> Result<ReplSessionInfo, String> {
    let response_session_id = session_id.clone();
    with_session(&session_id, move |session| {
        let state = session
            .lock()
            .map_err(|_| "REPL session is unavailable".to_string())?;
        Ok(session_info(response_session_id, &state))
    })
}

#[tauri::command]
pub fn repl_eval(request: ReplEvalRequest) -> Result<ReplEvalResponse, String> {
    let response_session_id = request.session_id.clone();
    let scope_session_id = request.session_id.clone();
    with_session(&request.session_id, move |session| {
        let mut engine = Engine::new();
        register_analysis_fns(&mut engine, Arc::clone(&session));

        let mut scope = Scope::new();
        {
            let state = session
                .lock()
                .map_err(|_| "REPL session is unavailable".to_string())?;
            scope.push("session_id", scope_session_id.clone());
            scope.push("path", state.path.clone());
        }

        let result = engine
            .eval_with_scope::<Dynamic>(&mut scope, &request.code)
            .map_err(|e| format!("Rhai evaluation failed: {e}"))?;
        let result_json = dynamic_to_json(result).map_err(|e| e.to_string())?;

        let mut state = session
            .lock()
            .map_err(|_| "REPL session is unavailable".to_string())?;
        state.eval_count += 1;
        let mut stored_keys: Vec<String> = state.stored.keys().cloned().collect();
        stored_keys.sort();

        Ok(ReplEvalResponse {
            session_id: response_session_id,
            path: state.path.clone(),
            result: result_json,
            eval_count: state.eval_count,
            stored_keys,
        })
    })
}