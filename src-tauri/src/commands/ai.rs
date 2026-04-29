use keyring::Entry;
use regex::Regex;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::Duration;

const DEFAULT_TIMEOUT_MS: u64 = 30_000;
const MAX_TIMEOUT_MS: u64 = 120_000;
const DEFAULT_MAX_PROMPT_CHARS: usize = 24_000;
const MAX_PROMPT_CHARS: usize = 64_000;
const DEFAULT_TOKEN_BUDGET: usize = 4_096;
const MAX_TOKEN_BUDGET: usize = 16_384;
const DEFAULT_KEY_ALIAS: &str = "talon.default";
const KEYRING_SERVICE: &str = "HexHawk";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LlmQueryRequest {
    pub endpoint_url: String,
    pub model_name: String,
    pub prompt: String,
    pub timeout_ms: Option<u64>,
    pub max_prompt_chars: Option<usize>,
    pub token_budget: Option<usize>,
    pub approval_granted: bool,
    pub allow_remote_endpoint: bool,
    pub allow_agent_tools: bool,
    pub api_key: Option<String>,
    pub use_keychain_key: bool,
    pub key_alias: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LlmQueryResponse {
    pub content: String,
    pub redaction_count: usize,
    pub prompt_chars: usize,
    pub token_estimate: usize,
    pub endpoint_host: String,
    pub model_name: String,
}

fn normalize_key_alias(alias: Option<String>) -> String {
    let raw = alias
        .unwrap_or_else(|| DEFAULT_KEY_ALIAS.to_string())
        .trim()
        .to_string();
    if raw.is_empty() {
        return DEFAULT_KEY_ALIAS.to_string();
    }
    raw.chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '_' || *c == '-')
        .take(64)
        .collect::<String>()
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

fn estimate_tokens(text: &str) -> usize {
    // Heuristic: ~4 chars/token for mixed code + prose prompts.
    ((text.chars().count() as f64) / 4.0).ceil() as usize
}

fn is_local_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

fn validate_endpoint(endpoint: &str, allow_remote_endpoint: bool) -> Result<Url, String> {
    let parsed = Url::parse(endpoint).map_err(|e| format!("Invalid endpoint URL: {e}"))?;

    let scheme = parsed.scheme();
    if scheme != "http" && scheme != "https" {
        return Err("Only http/https endpoints are allowed.".to_string());
    }

    let host = parsed
        .host_str()
        .ok_or_else(|| "Endpoint URL must include a hostname.".to_string())?;

    if !allow_remote_endpoint && !is_local_host(host) {
        return Err(
            "Remote endpoints are disabled. Enable explicit remote opt-in to continue.".to_string(),
        );
    }

    Ok(parsed)
}

fn extract_content(body: &Value) -> Option<String> {
    if let Some(choices) = body.get("choices").and_then(|v| v.as_array()) {
        if let Some(content) = choices
            .first()
            .and_then(|c| c.get("message"))
            .and_then(|m| m.get("content"))
            .and_then(|c| c.as_str())
        {
            return Some(content.to_string());
        }
    }

    if let Some(content) = body
        .get("message")
        .and_then(|m| m.get("content"))
        .and_then(|c| c.as_str())
    {
        return Some(content.to_string());
    }

    None
}

fn contains_tool_directive(content: &str) -> bool {
    let s = content.to_ascii_lowercase();
    s.contains("\"tool_calls\"")
        || s.contains("\"function_call\"")
        || s.contains("<tool")
        || s.contains("tool:")
}

fn load_api_key(alias: &str) -> Result<Option<String>, String> {
    let entry = Entry::new(KEYRING_SERVICE, alias)
        .map_err(|e| format!("Failed to access keychain entry: {e}"))?;

    match entry.get_password() {
        Ok(v) => Ok(Some(v)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(format!("Failed to read keychain secret: {e}")),
    }
}

#[tauri::command]
pub fn store_llm_api_key(key_alias: Option<String>, api_key: String) -> Result<(), String> {
    let alias = normalize_key_alias(key_alias);
    if alias.is_empty() {
        return Err("Key alias must not be empty.".to_string());
    }

    let trimmed = api_key.trim();
    if trimmed.len() < 8 {
        return Err("API key appears invalid (too short).".to_string());
    }

    let entry = Entry::new(KEYRING_SERVICE, &alias)
        .map_err(|e| format!("Failed to access keychain entry: {e}"))?;
    entry
        .set_password(trimmed)
        .map_err(|e| format!("Failed to store API key in keychain: {e}"))?;

    Ok(())
}

#[tauri::command]
pub fn clear_llm_api_key(key_alias: Option<String>) -> Result<(), String> {
    let alias = normalize_key_alias(key_alias);
    let entry = Entry::new(KEYRING_SERVICE, &alias)
        .map_err(|e| format!("Failed to access keychain entry: {e}"))?;

    match entry.delete_credential() {
        Ok(_) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(format!("Failed to clear keychain API key: {e}")),
    }
}

#[tauri::command]
pub fn has_llm_api_key(key_alias: Option<String>) -> Result<bool, String> {
    let alias = normalize_key_alias(key_alias);
    Ok(load_api_key(&alias)?.is_some())
}

#[tauri::command]
pub async fn llm_query(request: LlmQueryRequest) -> Result<LlmQueryResponse, String> {
    if !request.approval_granted {
        return Err("LLM query requires explicit user approval.".to_string());
    }

    let endpoint = validate_endpoint(&request.endpoint_url, request.allow_remote_endpoint)?;

    let prompt_limit = request
        .max_prompt_chars
        .unwrap_or(DEFAULT_MAX_PROMPT_CHARS)
        .clamp(1, MAX_PROMPT_CHARS);
    let token_budget = request
        .token_budget
        .unwrap_or(DEFAULT_TOKEN_BUDGET)
        .clamp(256, MAX_TOKEN_BUDGET);
    let timeout_ms = request
        .timeout_ms
        .unwrap_or(DEFAULT_TIMEOUT_MS)
        .clamp(1_000, MAX_TIMEOUT_MS);

    if request.prompt.trim().is_empty() {
        return Err("Prompt must not be empty.".to_string());
    }
    if request.prompt.chars().count() > prompt_limit {
        return Err(format!(
            "Prompt exceeds maximum size ({} chars, max {}).",
            request.prompt.chars().count(),
            prompt_limit
        ));
    }

    let (prompt_redacted, redaction_count) = redact_sensitive_text(&request.prompt);
    let token_estimate = estimate_tokens(&prompt_redacted);
    if token_estimate > token_budget {
        return Err(format!(
            "Prompt token estimate {} exceeds token budget {}.",
            token_estimate, token_budget
        ));
    }

    let alias = normalize_key_alias(request.key_alias.clone());
    let mut api_key = request.api_key.clone().map(|s| s.trim().to_string());
    if request.use_keychain_key && api_key.as_deref().unwrap_or("").is_empty() {
        api_key = load_api_key(&alias)?;
    }

    let is_openai_compat = api_key
        .as_ref()
        .map(|k| !k.is_empty())
        .unwrap_or(false);

    let max_output_tokens = (token_budget / 2).clamp(64, 2_048) as u64;

    let body = if is_openai_compat {
        serde_json::json!({
            "model": request.model_name,
            "messages": [{"role": "user", "content": prompt_redacted}],
            "response_format": {"type": "json_object"},
            "tool_choice": "none",
            "parallel_tool_calls": false,
            "max_tokens": max_output_tokens,
        })
    } else {
        serde_json::json!({
            "model": request.model_name,
            "messages": [{"role": "user", "content": prompt_redacted}],
            "stream": false,
            "format": "json",
            "options": { "num_predict": max_output_tokens },
        })
    };

    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::CONTENT_TYPE,
        reqwest::header::HeaderValue::from_static("application/json"),
    );

    if let Some(key) = api_key {
        if !key.is_empty() {
            let bearer = format!("Bearer {key}");
            let value = reqwest::header::HeaderValue::from_str(&bearer)
                .map_err(|_| "Invalid API key header value.".to_string())?;
            headers.insert(reqwest::header::AUTHORIZATION, value);
        }
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(timeout_ms))
        .build()
        .map_err(|e| format!("Failed to build HTTP client: {e}"))?;

    let host = endpoint.host_str().unwrap_or("unknown").to_string();
    log::info!(
        "llm_query approved host={} model={} prompt_chars={} token_estimate={} redactions={} remote_allowed={} tools_allowed={}",
        host,
        request.model_name,
        prompt_redacted.chars().count(),
        token_estimate,
        redaction_count,
        request.allow_remote_endpoint,
        request.allow_agent_tools,
    );

    let response = client
        .post(endpoint)
        .headers(headers)
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("LLM request failed: {e}"))?;

    let status = response.status();
    let value: Value = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse LLM response JSON: {e}"))?;

    if !status.is_success() {
        return Err(format!("LLM endpoint returned HTTP {}", status.as_u16()));
    }

    let content = extract_content(&value)
        .ok_or_else(|| "Unexpected LLM response shape: missing content.".to_string())?;

    if !request.allow_agent_tools && contains_tool_directive(&content) {
        return Err("LLM response included tool directives without explicit tool approval.".to_string());
    }

    Ok(LlmQueryResponse {
        content,
        redaction_count,
        prompt_chars: prompt_redacted.chars().count(),
        token_estimate,
        endpoint_host: host,
        model_name: request.model_name,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_sensitive_text_masks_keys() {
        let input = "Authorization: Bearer sk-THISISALONGSECRETKEY1234";
        let (out, count) = redact_sensitive_text(input);
        assert!(count >= 1);
        assert!(out.contains("[REDACTED]"));
        assert!(!out.contains("THISISALONGSECRETKEY"));
    }

    #[test]
    fn estimate_tokens_grows_with_input() {
        let small = estimate_tokens("abcd");
        let big = estimate_tokens("abcd".repeat(200).as_str());
        assert!(big > small);
    }

    #[test]
    fn normalize_key_alias_sanitizes_chars() {
        let alias = normalize_key_alias(Some(".. bad alias !!".to_string()));
        assert!(alias.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-'));
        assert!(!alias.is_empty());
    }

    #[test]
    fn contains_tool_directive_detects_tool_payload() {
        assert!(contains_tool_directive("{\"tool_calls\": []}"));
        assert!(!contains_tool_directive("{\"renamedVariables\":{}}"));
    }

    #[test]
    fn validate_endpoint_blocks_remote_when_not_allowed() {
        let err = validate_endpoint("https://api.openai.com/v1/chat/completions", false).unwrap_err();
        assert!(err.contains("Remote endpoints are disabled"));
    }

    #[test]
    fn validate_endpoint_allows_localhost_when_remote_disallowed() {
        let ok = validate_endpoint("http://localhost:11434/api/chat", false);
        assert!(ok.is_ok());
    }

    #[test]
    fn redact_sensitive_text_masks_multiple_secret_formats() {
        let input = "Authorization: Bearer sk-SECRETKEY123456\napi_key=topsecret\nx-api-key: abcdef\nsk-ANOTHERSECRET999";
        let (out, count) = redact_sensitive_text(input);
        assert!(count >= 4);
        assert!(!out.contains("SECRETKEY123456"));
        assert!(!out.contains("topsecret"));
        assert!(!out.contains("abcdef"));
        assert!(out.contains("[REDACTED]"));
    }
}
