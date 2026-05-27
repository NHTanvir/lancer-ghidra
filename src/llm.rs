//! Live LLM client — POSTs an `ai-decompile` prompt to Anthropic's Messages
//! API and prints the response.
//!
//! Auth: `ANTHROPIC_API_KEY` environment variable. If unset, the call fails
//! with a helpful message rather than silently no-op'ing.
//!
//! Default model is `claude-opus-4-7` per the global config in CLAUDE.md
//! (Opus 4.7 is the latest Anthropic flagship as of 2026-05).

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::time::Duration;

const ANTHROPIC_URL: &str = "https://api.anthropic.com/v1/messages";
const ANTHROPIC_VERSION: &str = "2023-06-01";
const DEFAULT_MODEL: &str = "claude-opus-4-7";
const DEFAULT_MAX_TOKENS: u32 = 4096;

#[derive(Serialize)]
struct Request<'a> {
    model: &'a str,
    max_tokens: u32,
    messages: Vec<Message<'a>>,
}

#[derive(Serialize)]
struct Message<'a> {
    role: &'a str,
    content: &'a str,
}

#[derive(Deserialize, Debug)]
struct Response {
    content: Vec<ResponseBlock>,
    #[serde(default)]
    model: String,
    #[serde(default)]
    stop_reason: String,
}

#[derive(Deserialize, Debug)]
#[serde(tag = "type")]
enum ResponseBlock {
    #[serde(rename = "text")]
    Text { text: String },
    #[serde(other)]
    Other,
}

pub struct LlmConfig {
    pub model: String,
    pub max_tokens: u32,
    pub timeout: Duration,
}

impl Default for LlmConfig {
    fn default() -> Self {
        Self {
            model: DEFAULT_MODEL.to_string(),
            max_tokens: DEFAULT_MAX_TOKENS,
            timeout: Duration::from_secs(120),
        }
    }
}

pub fn send_prompt(prompt: &str, cfg: &LlmConfig) -> Result<String> {
    let api_key = std::env::var("ANTHROPIC_API_KEY")
        .context("ANTHROPIC_API_KEY not set — export it before using --send")?;

    let body = Request {
        model: &cfg.model,
        max_tokens: cfg.max_tokens,
        messages: vec![Message {
            role: "user",
            content: prompt,
        }],
    };

    let agent = ureq::AgentBuilder::new()
        .timeout(cfg.timeout)
        .build();

    let res = agent
        .post(ANTHROPIC_URL)
        .set("x-api-key", &api_key)
        .set("anthropic-version", ANTHROPIC_VERSION)
        .set("content-type", "application/json")
        .send_json(serde_json::to_value(&body)?);

    let res = match res {
        Ok(r) => r,
        Err(ureq::Error::Status(code, response)) => {
            let body = response
                .into_string()
                .unwrap_or_else(|_| "<no body>".to_string());
            return Err(anyhow!("Anthropic API error {code}: {body}"));
        }
        Err(e) => return Err(anyhow!("Anthropic API call failed: {e}")),
    };

    let parsed: Response = res
        .into_json()
        .context("failed to parse Anthropic response JSON")?;

    let mut out = String::new();
    for block in parsed.content {
        if let ResponseBlock::Text { text } = block {
            out.push_str(&text);
        }
    }
    if out.is_empty() {
        return Err(anyhow!(
            "Anthropic returned no text content (model={}, stop_reason={})",
            parsed.model,
            parsed.stop_reason
        ));
    }
    Ok(out)
}
