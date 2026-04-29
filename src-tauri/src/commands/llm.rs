use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use keyring::Entry;
use rand::RngCore;
use regex::Regex;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::PathBuf;
use std::time::Duration;
use tauri::Manager;
use tauri_plugin_stronghold::stronghold::Stronghold;

const DEFAULT_TIMEOUT_MS: u64 = 30_000;
const MAX_TIMEOUT_MS: u64 = 90_000;
const DEFAULT_MAX_PROMPT_CHARS: usize = 24_000;
const MAX_PROMPT_CHARS: usize = 64_000;
const DEFAULT_MAX_CONTEXT_CHARS: usize = 48_000;
const MAX_CONTEXT_CHARS: usize = 120_000;
const DEFAULT_TOKEN_BUDGET: usize = 4_096;
const MAX_TOKEN_BUDGET: usize = 16_384;
const MAX_CONTEXT_BLOCKS: usize = 32;

const DEFAULT_KEY_ALIAS: &str = "default";
const STRONGHOLD_CLIENT_ID: &str = "hexhawk-llm-client";
const STRONGHOLD_MASTER_SERVICE: &str = "HexHawkStronghold";
const STRONGHOLD_MASTER_ACCOUNT: &str = "llm.master";

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LlmProvider {
    OpenAi,
    Anthropic,
    Ollama,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LlmAction {
    SignalExplainer,
    AerieMode,
    TalonNarrate,
    CrestNarration,
    BinaryDiffInsight,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LlmQueryRequest {
    pub provider: Option<LlmProvider>,
    pub action: Option<LlmAction>,
    pub endpoint_url: String,
    pub model_name: String,
    pub prompt: String,
    pub context_blocks: Option<Vec<String>>,
    pub timeout_ms: Option<u64>,
    pub max_prompt_chars: Option<usize>,
    pub max_context_chars: Option<usize>,
    pub token_budget: Option<usize>,
    pub approval_granted: bool,
    pub allow_remote_endpoint: bool,
    pub allow_agent_tools: bool,
    pub key_alias: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LlmQueryResponse {
    pub advisory_only: bool,
    pub provider: LlmProvider,
    pub action: LlmAction,
    pub model_name: String,
    pub endpoint_host: String,
    pub content: String,
    pub redaction_count: usize,
    pub prompt_chars: usize,
    pub context_chars: usize,
    pub token_estimate: usize,
    pub estimated_cost_usd: Option<f64>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderKeyRequest {
    pub provider: LlmProvider,
    pub key_alias: Option<String>,
    pub api_key: String,
}

#[derive(Debug, thiserror::Error)]
enum LlmError {
    #[error("explicit approval is required before sending data to a provider")]
    ApprovalRequired,
    #[error("prompt is empty")]
    EmptyPrompt,
    #[error("prompt exceeds maximum allowed size")]
    PromptTooLarge,
    #[error("context exceeds maximum allowed size")]
    ContextTooLarge,
    #[error("too many context blocks")]
    TooManyContextBlocks,
    #[error("token budget exceeded")]
    TokenBudgetExceeded,
    #[error("provider endpoint is invalid")]
    InvalidEndpoint,
    #[error("remote endpoints are disabled")]
    RemoteEndpointDisabled,
    #[error("api key lookup failed")]
    KeyLookupFailed,
    #[error("provider timeout")]
    ProviderTimeout,
    #[error("provider returned malformed response")]
    MalformedProviderResponse,
    #[error("provider request failed")]
    ProviderRequestFailed,
    #[error("stronghold storage operation failed")]
    SecretStoreFailed,
    #[error("provider requires an API key")]
    MissingApiKey,
    #[error("provider output contains tool directives while tools are disallowed")]
    ToolDirectiveBlocked,
}

type LlmResult<T> = Result<T, LlmError>;

trait SecretStore {
    fn store_provider_key(&self, provider: &LlmProvider, alias: &str, key: &str) -> LlmResult<()>;
    fn load_provider_key(&self, provider: &LlmProvider, alias: &str) -> LlmResult<Option<String>>;
    fn clear_provider_key(&self, provider: &LlmProvider, alias: &str) -> LlmResult<()>;
    fn has_provider_key(&self, provider: &LlmProvider, alias: &str) -> LlmResult<bool>;
}

struct StrongholdSecretStore {
    vault_path: PathBuf,
}

impl StrongholdSecretStore {
    fn from_app(app: &tauri::AppHandle) -> LlmResult<Self> {
        let dir = app
            .path()
            .app_local_data_dir()
            .map_err(|_| LlmError::SecretStoreFailed)?;
        std::fs::create_dir_all(&dir).map_err(|_| LlmError::SecretStoreFailed)?;
        Ok(Self {
            vault_path: dir.join("llm-keys.hold"),
        })
    }

    fn load_or_create_master_key() -> LlmResult<Vec<u8>> {
        let entry = Entry::new(STRONGHOLD_MASTER_SERVICE, STRONGHOLD_MASTER_ACCOUNT)
            .map_err(|_| LlmError::SecretStoreFailed)?;

        match entry.get_password() {
            Ok(encoded) => {
                let bytes = B64.decode(encoded.as_bytes()).map_err(|_| LlmError::SecretStoreFailed)?;
                if bytes.len() != 32 {
                    return Err(LlmError::SecretStoreFailed);
                }
                Ok(bytes)
            }
            Err(keyring::Error::NoEntry) => {
                let mut bytes = vec![0u8; 32];
                rand::thread_rng().fill_bytes(&mut bytes);
                let encoded = B64.encode(&bytes);
                entry
                    .set_password(&encoded)
                    .map_err(|_| LlmError::SecretStoreFailed)?;
                Ok(bytes)
            }
            Err(_) => Err(LlmError::SecretStoreFailed),
        }
    }

    fn open_stronghold(&self) -> LlmResult<Stronghold> {
        let password = Self::load_or_create_master_key()?;
        Stronghold::new(&self.vault_path, password).map_err(|_| LlmError::SecretStoreFailed)
    }

    fn with_client<F, T>(&self, mut f: F) -> LlmResult<T>
    where
        F: FnMut(&iota_stronghold::Client) -> LlmResult<T>,
    {
        let stronghold = self.open_stronghold()?;
        let client_id = STRONGHOLD_CLIENT_ID.as_bytes().to_vec();

        if stronghold.get_client(client_id.clone()).is_err() {
            stronghold
                .create_client(client_id.clone())
                .map_err(|_| LlmError::SecretStoreFailed)?;
        }

        let client = stronghold
            .get_client(client_id)
            .map_err(|_| LlmError::SecretStoreFailed)?;

        let out = f(&client)?;
        stronghold.save().map_err(|_| LlmError::SecretStoreFailed)?;
        Ok(out)
    }

    fn key(provider: &LlmProvider, alias: &str) -> String {
        format!("provider:{}:alias:{}", provider_id(provider), alias)
    }
}

impl SecretStore for StrongholdSecretStore {
    fn store_provider_key(&self, provider: &LlmProvider, alias: &str, key: &str) -> LlmResult<()> {
        self.with_client(|client| {
            client
                .store()
                .insert(Self::key(provider, alias).into_bytes(), key.as_bytes().to_vec(), None)
                .map_err(|_| LlmError::SecretStoreFailed)?;
            Ok(())
        })
    }

    fn load_provider_key(&self, provider: &LlmProvider, alias: &str) -> LlmResult<Option<String>> {
        self.with_client(|client| {
            let raw = client
                .store()
                .get(Self::key(provider, alias).as_bytes())
                .map_err(|_| LlmError::SecretStoreFailed)?;
            let out = raw
                .map(|v| String::from_utf8(v).map_err(|_| LlmError::SecretStoreFailed))
                .transpose()?;
            Ok(out)
        })
    }

    fn clear_provider_key(&self, provider: &LlmProvider, alias: &str) -> LlmResult<()> {
        self.with_client(|client| {
            let _ = client
                .store()
                .delete(Self::key(provider, alias).as_bytes())
                .map_err(|_| LlmError::SecretStoreFailed)?;
            Ok(())
        })
    }

    fn has_provider_key(&self, provider: &LlmProvider, alias: &str) -> LlmResult<bool> {
        Ok(self.load_provider_key(provider, alias)?.is_some())
    }
}

trait HttpExecutor {
    fn execute(
        &self,
        endpoint: Url,
        timeout: Duration,
        headers: reqwest::header::HeaderMap,
        body: Value,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(u16, Value), HttpExecError>> + Send>>;
}

#[derive(Debug)]
enum HttpExecError {
    Timeout,
    Request,
}

struct ReqwestExecutor;

impl HttpExecutor for ReqwestExecutor {
    fn execute(
        &self,
        endpoint: Url,
        timeout: Duration,
        headers: reqwest::header::HeaderMap,
        body: Value,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(u16, Value), HttpExecError>> + Send>> {
        Box::pin(async move {
            let client = reqwest::Client::builder()
                .timeout(timeout)
                .build()
                .map_err(|_| HttpExecError::Request)?;
            let resp = client
                .post(endpoint)
                .headers(headers)
                .json(&body)
                .send()
                .await
                .map_err(|e| if e.is_timeout() { HttpExecError::Timeout } else { HttpExecError::Request })?;
            let status = resp.status().as_u16();
            let json: Value = resp.json().await.map_err(|_| HttpExecError::Request)?;
            Ok((status, json))
        })
    }
}

fn provider_id(provider: &LlmProvider) -> &'static str {
    match provider {
        LlmProvider::OpenAi => "openai",
        LlmProvider::Anthropic => "anthropic",
        LlmProvider::Ollama => "ollama",
    }
}

fn normalize_alias(alias: Option<String>) -> String {
    let raw = alias.unwrap_or_else(|| DEFAULT_KEY_ALIAS.to_string());
    let sanitized: String = raw
        .trim()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '_' || *c == '-')
        .take(64)
        .collect();
    if sanitized.is_empty() {
        DEFAULT_KEY_ALIAS.to_string()
    } else {
        sanitized
    }
}

fn redaction_patterns() -> Vec<(Regex, &'static str)> {
    vec![
        (
            Regex::new(r#"(?i)authorization\s*:\s*bearer\s+[^\s\"]+"#).unwrap(),
            "Authorization: Bearer [REDACTED]",
        ),
        (Regex::new(r#"\bsk-[A-Za-z0-9_-]{12,}\b"#).unwrap(), "[REDACTED]"),
        (
            Regex::new(r#"(?i)(api[_-]?key\s*[:=]\s*)[^\s\"'`]+"#).unwrap(),
            "$1[REDACTED]",
        ),
        (
            Regex::new(r#"(?i)(x-api-key\s*[:=]\s*)[^\s\"'`]+"#).unwrap(),
            "$1[REDACTED]",
        ),
    ]
}

fn redact_sensitive_text(input: &str) -> (String, usize) {
    let mut out = input.to_string();
    let mut count = 0usize;
    for (re, replacement) in redaction_patterns() {
        let matches = re.find_iter(&out).count();
        if matches > 0 {
            count += matches;
            out = re.replace_all(&out, replacement).to_string();
        }
    }
    (out, count)
}

fn estimate_tokens(chars: usize) -> usize {
    ((chars as f64) / 4.0).ceil() as usize
}

fn is_local_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

fn validate_endpoint(endpoint: &str, allow_remote_endpoint: bool) -> LlmResult<Url> {
    let parsed = Url::parse(endpoint).map_err(|_| LlmError::InvalidEndpoint)?;
    let scheme = parsed.scheme();
    if scheme != "http" && scheme != "https" {
        return Err(LlmError::InvalidEndpoint);
    }

    let host = parsed.host_str().ok_or(LlmError::InvalidEndpoint)?;
    if !allow_remote_endpoint && !is_local_host(host) {
        return Err(LlmError::RemoteEndpointDisabled);
    }

    Ok(parsed)
}

fn contains_tool_directive(content: &str) -> bool {
    let s = content.to_ascii_lowercase();
    s.contains("\"tool_calls\"")
        || s.contains("\"function_call\"")
        || s.contains("<tool")
        || s.contains("tool:")
}

fn extract_provider_content(provider: &LlmProvider, body: &Value) -> LlmResult<String> {
    match provider {
        LlmProvider::OpenAi => body
            .get("choices")
            .and_then(|v| v.as_array())
            .and_then(|choices| choices.first())
            .and_then(|c| c.get("message"))
            .and_then(|m| m.get("content"))
            .and_then(|c| c.as_str())
            .map(|s| s.to_string())
            .ok_or(LlmError::MalformedProviderResponse),
        LlmProvider::Anthropic => body
            .get("content")
            .and_then(|v| v.as_array())
            .and_then(|items| items.iter().find_map(|it| {
                if it.get("type").and_then(|t| t.as_str()) == Some("text") {
                    it.get("text").and_then(|t| t.as_str())
                } else {
                    None
                }
            }))
            .map(|s| s.to_string())
            .ok_or(LlmError::MalformedProviderResponse),
        LlmProvider::Ollama => body
            .get("message")
            .and_then(|m| m.get("content"))
            .and_then(|c| c.as_str())
            .map(|s| s.to_string())
            .ok_or(LlmError::MalformedProviderResponse),
    }
}

fn estimate_cost_usd(provider: &LlmProvider, token_estimate: usize) -> Option<f64> {
    let rate_per_1k = match provider {
        LlmProvider::OpenAi => Some(0.005_f64),
        LlmProvider::Anthropic => Some(0.008_f64),
        LlmProvider::Ollama => None,
    }?;

    let cost = (token_estimate as f64 / 1000.0) * rate_per_1k;
    Some((cost * 10000.0).round() / 10000.0)
}

fn merge_prompt_and_context(req: &LlmQueryRequest) -> LlmResult<(String, usize, usize, usize)> {
    if req.prompt.trim().is_empty() {
        return Err(LlmError::EmptyPrompt);
    }

    let prompt_limit = req
        .max_prompt_chars
        .unwrap_or(DEFAULT_MAX_PROMPT_CHARS)
        .clamp(1, MAX_PROMPT_CHARS);
    let context_limit = req
        .max_context_chars
        .unwrap_or(DEFAULT_MAX_CONTEXT_CHARS)
        .clamp(0, MAX_CONTEXT_CHARS);

    let prompt_chars = req.prompt.chars().count();
    if prompt_chars > prompt_limit {
        return Err(LlmError::PromptTooLarge);
    }

    let ctx = req.context_blocks.clone().unwrap_or_default();
    if ctx.len() > MAX_CONTEXT_BLOCKS {
        return Err(LlmError::TooManyContextBlocks);
    }

    let context_chars: usize = ctx.iter().map(|s| s.chars().count()).sum();
    if context_chars > context_limit {
        return Err(LlmError::ContextTooLarge);
    }

    let mut merged = String::with_capacity(req.prompt.len() + context_chars + 64);
    merged.push_str(req.prompt.trim());
    if !ctx.is_empty() {
        merged.push_str("\n\n[CONTEXT]\n");
        for (i, block) in ctx.iter().enumerate() {
            merged.push_str("- block ");
            merged.push_str(&(i + 1).to_string());
            merged.push_str(": ");
            merged.push_str(block);
            merged.push('\n');
        }
    }

    let combined_chars = merged.chars().count();
    let token_estimate = estimate_tokens(combined_chars);
    let budget = req
        .token_budget
        .unwrap_or(DEFAULT_TOKEN_BUDGET)
        .clamp(256, MAX_TOKEN_BUDGET);
    if token_estimate > budget {
        return Err(LlmError::TokenBudgetExceeded);
    }

    Ok((merged, prompt_chars, context_chars, token_estimate))
}

fn infer_provider(req: &LlmQueryRequest) -> LlmProvider {
    if let Some(p) = &req.provider {
        return p.clone();
    }

    let endpoint = req.endpoint_url.to_ascii_lowercase();
    if endpoint.contains("anthropic") {
        return LlmProvider::Anthropic;
    }
    if endpoint.contains("openai") {
        return LlmProvider::OpenAi;
    }
    LlmProvider::Ollama
}

async fn llm_query_core<S: SecretStore, E: HttpExecutor>(
    req: LlmQueryRequest,
    store: &S,
    executor: &E,
) -> LlmResult<LlmQueryResponse> {
    if !req.approval_granted {
        return Err(LlmError::ApprovalRequired);
    }

    let provider = infer_provider(&req);
    let action = req.action.clone().unwrap_or(LlmAction::TalonNarrate);
    let endpoint = validate_endpoint(&req.endpoint_url, req.allow_remote_endpoint)?;

    let (combined, prompt_chars, context_chars, token_estimate) = merge_prompt_and_context(&req)?;
    let (redacted_prompt, redaction_count) = redact_sensitive_text(&combined);

    let alias = normalize_alias(req.key_alias.clone());
    let api_key = match provider {
        LlmProvider::Ollama => None,
        LlmProvider::OpenAi | LlmProvider::Anthropic => {
            store
                .load_provider_key(&provider, &alias)
                .map_err(|_| LlmError::KeyLookupFailed)?
        }
    };

    if matches!(provider, LlmProvider::OpenAi | LlmProvider::Anthropic) && api_key.is_none() {
        return Err(LlmError::MissingApiKey);
    }

    let timeout_ms = req
        .timeout_ms
        .unwrap_or(DEFAULT_TIMEOUT_MS)
        .clamp(1000, MAX_TIMEOUT_MS);
    let timeout = Duration::from_millis(timeout_ms);

    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::CONTENT_TYPE,
        reqwest::header::HeaderValue::from_static("application/json"),
    );

    let max_output_tokens = (req
        .token_budget
        .unwrap_or(DEFAULT_TOKEN_BUDGET)
        .clamp(256, MAX_TOKEN_BUDGET)
        / 2)
        .clamp(64, 2048) as u64;

    let body = match provider {
        LlmProvider::OpenAi => {
            if let Some(key) = api_key.as_deref() {
                let bearer = format!("Bearer {key}");
                let value = reqwest::header::HeaderValue::from_str(&bearer)
                    .map_err(|_| LlmError::ProviderRequestFailed)?;
                headers.insert(reqwest::header::AUTHORIZATION, value);
            }
            serde_json::json!({
                "model": req.model_name,
                "messages": [{"role": "user", "content": redacted_prompt}],
                "response_format": {"type": "json_object"},
                "tool_choice": "none",
                "parallel_tool_calls": false,
                "max_tokens": max_output_tokens,
            })
        }
        LlmProvider::Anthropic => {
            if let Some(key) = api_key.as_deref() {
                headers.insert(
                    "x-api-key",
                    reqwest::header::HeaderValue::from_str(key)
                        .map_err(|_| LlmError::ProviderRequestFailed)?,
                );
            }
            headers.insert(
                "anthropic-version",
                reqwest::header::HeaderValue::from_static("2023-06-01"),
            );
            serde_json::json!({
                "model": req.model_name,
                "max_tokens": max_output_tokens,
                "messages": [{"role": "user", "content": redacted_prompt}],
            })
        }
        LlmProvider::Ollama => serde_json::json!({
            "model": req.model_name,
            "messages": [{"role": "user", "content": redacted_prompt}],
            "stream": false,
            "format": "json",
            "options": { "num_predict": max_output_tokens },
        }),
    };

    log::info!(
        "llm_query action={} provider={} model={} endpoint_host={} prompt_chars={} context_chars={} token_estimate={} redactions={} remote_allowed={} tools_allowed={}",
        serde_json::to_string(&action).unwrap_or_else(|_| "\"unknown\"".to_string()),
        provider_id(&provider),
        req.model_name,
        endpoint.host_str().unwrap_or("unknown"),
        prompt_chars,
        context_chars,
        token_estimate,
        redaction_count,
        req.allow_remote_endpoint,
        req.allow_agent_tools,
    );

    let (status, body) = executor
        .execute(endpoint.clone(), timeout, headers, body)
        .await
        .map_err(|e| match e {
            HttpExecError::Timeout => LlmError::ProviderTimeout,
            HttpExecError::Request => LlmError::ProviderRequestFailed,
        })?;

    if status < 200 || status >= 300 {
        return Err(LlmError::ProviderRequestFailed);
    }

    let content = extract_provider_content(&provider, &body)?;

    if !req.allow_agent_tools && contains_tool_directive(&content) {
        return Err(LlmError::ToolDirectiveBlocked);
    }

    let warnings = vec![
        "AI output is advisory only and must not directly mutate verdict state.".to_string(),
    ];
    let estimated_cost_usd = estimate_cost_usd(&provider, token_estimate);

    Ok(LlmQueryResponse {
        advisory_only: true,
        provider,
        action,
        model_name: req.model_name,
        endpoint_host: endpoint.host_str().unwrap_or("unknown").to_string(),
        content,
        redaction_count,
        prompt_chars,
        context_chars,
        token_estimate,
        estimated_cost_usd,
        warnings,
    })
}

#[tauri::command]
pub fn store_llm_provider_key(
    app: tauri::AppHandle,
    request: ProviderKeyRequest,
) -> Result<(), String> {
    let alias = normalize_alias(request.key_alias);
    let key = request.api_key.trim();
    if key.len() < 8 {
        return Err("API key appears invalid (too short).".to_string());
    }

    let store = StrongholdSecretStore::from_app(&app).map_err(|e| e.to_string())?;
    store
        .store_provider_key(&request.provider, &alias, key)
        .map_err(|e| e.to_string())?;

    Ok(())
}

#[tauri::command]
pub fn clear_llm_provider_key(
    app: tauri::AppHandle,
    provider: LlmProvider,
    key_alias: Option<String>,
) -> Result<(), String> {
    let alias = normalize_alias(key_alias);
    let store = StrongholdSecretStore::from_app(&app).map_err(|e| e.to_string())?;
    store
        .clear_provider_key(&provider, &alias)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn has_llm_provider_key(
    app: tauri::AppHandle,
    provider: LlmProvider,
    key_alias: Option<String>,
) -> Result<bool, String> {
    let alias = normalize_alias(key_alias);
    let store = StrongholdSecretStore::from_app(&app).map_err(|e| e.to_string())?;
    store
        .has_provider_key(&provider, &alias)
        .map_err(|e| e.to_string())
}

// Backward-compatible wrappers for existing TALON settings UI.
#[tauri::command]
pub fn store_llm_api_key(
    app: tauri::AppHandle,
    key_alias: Option<String>,
    api_key: String,
) -> Result<(), String> {
    store_llm_provider_key(
        app,
        ProviderKeyRequest {
            provider: LlmProvider::OpenAi,
            key_alias,
            api_key,
        },
    )
}

#[tauri::command]
pub fn clear_llm_api_key(app: tauri::AppHandle, key_alias: Option<String>) -> Result<(), String> {
    clear_llm_provider_key(app, LlmProvider::OpenAi, key_alias)
}

#[tauri::command]
pub fn has_llm_api_key(app: tauri::AppHandle, key_alias: Option<String>) -> Result<bool, String> {
    has_llm_provider_key(app, LlmProvider::OpenAi, key_alias)
}

#[tauri::command]
pub async fn llm_query(app: tauri::AppHandle, request: LlmQueryRequest) -> Result<LlmQueryResponse, String> {
    let store = StrongholdSecretStore::from_app(&app).map_err(|e| e.to_string())?;
    let executor = ReqwestExecutor;
    llm_query_core(request, &store, &executor)
        .await
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    #[derive(Default)]
    struct MemoryStore {
        map: Mutex<HashMap<String, String>>,
        fail_load: bool,
    }

    impl SecretStore for MemoryStore {
        fn store_provider_key(&self, provider: &LlmProvider, alias: &str, key: &str) -> LlmResult<()> {
            self.map
                .lock()
                .unwrap()
                .insert(format!("{}:{}", provider_id(provider), alias), key.to_string());
            Ok(())
        }

        fn load_provider_key(&self, provider: &LlmProvider, alias: &str) -> LlmResult<Option<String>> {
            if self.fail_load {
                return Err(LlmError::KeyLookupFailed);
            }
            Ok(self
                .map
                .lock()
                .unwrap()
                .get(&format!("{}:{}", provider_id(provider), alias))
                .cloned())
        }

        fn clear_provider_key(&self, provider: &LlmProvider, alias: &str) -> LlmResult<()> {
            self.map
                .lock()
                .unwrap()
                .remove(&format!("{}:{}", provider_id(provider), alias));
            Ok(())
        }

        fn has_provider_key(&self, provider: &LlmProvider, alias: &str) -> LlmResult<bool> {
            Ok(self
                .map
                .lock()
                .unwrap()
                .contains_key(&format!("{}:{}", provider_id(provider), alias)))
        }
    }

    struct MockExec {
        outcome: Result<(u16, Value), String>,
    }

    impl HttpExecutor for MockExec {
        fn execute(
            &self,
            _endpoint: Url,
            _timeout: Duration,
            _headers: reqwest::header::HeaderMap,
            _body: Value,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(u16, Value), HttpExecError>> + Send>> {
            let out = self.outcome.clone();
            Box::pin(async move {
                match out {
                    Ok(v) => Ok(v),
                    Err(msg) if msg == "timeout" => Err(HttpExecError::Timeout),
                    Err(_) => Err(HttpExecError::Request),
                }
            })
        }
    }

    fn base_request() -> LlmQueryRequest {
        LlmQueryRequest {
            provider: Some(LlmProvider::OpenAi),
            action: Some(LlmAction::SignalExplainer),
            endpoint_url: "https://api.openai.com/v1/chat/completions".to_string(),
            model_name: "gpt-4o-mini".to_string(),
            prompt: "Explain this signal".to_string(),
            context_blocks: Some(vec!["signal details".to_string()]),
            timeout_ms: Some(2000),
            max_prompt_chars: Some(2000),
            max_context_chars: Some(2000),
            token_budget: Some(2048),
            approval_granted: true,
            allow_remote_endpoint: true,
            allow_agent_tools: false,
            key_alias: Some("default".to_string()),
        }
    }

    #[test]
    fn key_lookup_failure_returns_error() {
        let store = MemoryStore {
            fail_load: true,
            ..Default::default()
        };
        let exec = MockExec {
            outcome: Ok((200, serde_json::json!({"choices":[{"message":{"content":"{}"}}]}))),
        };
        let req = base_request();

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let result = rt.block_on(llm_query_core(req, &store, &exec));
        assert!(matches!(result, Err(LlmError::KeyLookupFailed)));
    }

    #[test]
    fn provider_timeout_returns_error() {
        let store = MemoryStore::default();
        store
            .store_provider_key(&LlmProvider::OpenAi, "default", "sk-test-key")
            .unwrap();
        let exec = MockExec {
            outcome: Err("timeout".to_string()),
        };

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let result = rt.block_on(llm_query_core(base_request(), &store, &exec));
        assert!(matches!(result, Err(LlmError::ProviderTimeout)));
    }

    #[test]
    fn malformed_provider_response_rejected() {
        let store = MemoryStore::default();
        store
            .store_provider_key(&LlmProvider::OpenAi, "default", "sk-test-key")
            .unwrap();
        let exec = MockExec {
            outcome: Ok((200, serde_json::json!({"unexpected":"shape"}))),
        };

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let result = rt.block_on(llm_query_core(base_request(), &store, &exec));
        assert!(matches!(result, Err(LlmError::MalformedProviderResponse)));
    }

    #[test]
    fn oversized_context_rejected() {
        let mut req = base_request();
        req.context_blocks = Some(vec!["A".repeat(5000)]);
        req.max_context_chars = Some(1000);

        let result = merge_prompt_and_context(&req);
        assert!(matches!(result, Err(LlmError::ContextTooLarge)));
    }

    #[test]
    fn token_budget_enforced() {
        let mut req = base_request();
        req.prompt = "B".repeat(20000);
        req.max_prompt_chars = Some(30000);
        req.token_budget = Some(100);

        let result = merge_prompt_and_context(&req);
        assert!(matches!(result, Err(LlmError::TokenBudgetExceeded)));
    }
}
