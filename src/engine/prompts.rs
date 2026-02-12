//! MCP prompt handler for the `coding_modern_rust` prompt.

use rmcp::model::{
    GetPromptResult, ListPromptsResult, Prompt, PromptArgument, PromptMessage,
    PromptMessageContent, PromptMessageRole,
};
use rmcp::{ErrorData as McpError, model::GetPromptRequestParams};

const GUIDE: &str = include_str!("../../prompts/coding_modern_rust.md");

pub fn list_prompts_impl() -> ListPromptsResult {
    ListPromptsResult {
        meta: None,
        next_cursor: None,
        prompts: vec![Prompt {
            name: "coding_modern_rust".into(),
            title: Some("Modern Rust Guide (2026)".into()),
            description: Some(
                "Comprehensive guide to writing idiomatic Rust in 2026. \
                 Covers edition 2024, new stable APIs (1.85-1.93), blessed crates, \
                 async patterns, error handling, anti-patterns, and defensive patterns. \
                 Optionally provide code for review against the guide."
                    .into(),
            ),
            arguments: Some(vec![PromptArgument {
                name: "code".into(),
                title: Some("Code to review".into()),
                description: Some(
                    "Optional Rust source code to review against the guide. \
                     When provided, the guide is returned along with a review request."
                        .into(),
                ),
                required: Some(false),
            }]),
            icons: None,
            meta: None,
        }],
    }
}

pub fn get_prompt(params: &GetPromptRequestParams) -> Result<GetPromptResult, McpError> {
    if params.name != "coding_modern_rust" {
        return Err(McpError::invalid_params(
            format!("Unknown prompt: {}", params.name),
            None,
        ));
    }

    let code = params
        .arguments
        .as_ref()
        .and_then(|args| args.get("code"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.trim().is_empty());

    let mut messages = vec![PromptMessage {
        role: PromptMessageRole::User,
        content: PromptMessageContent::Text {
            text: GUIDE.to_string(),
        },
    }];

    if let Some(code) = code {
        messages.push(PromptMessage {
            role: PromptMessageRole::User,
            content: PromptMessageContent::Text {
                text: format!(
                    "Review the following Rust code against the Modern Rust Guide above. \
                     Identify any anti-patterns, deprecated APIs, missing defensive patterns, \
                     or opportunities to use newer language features and blessed crates. \
                     Be specific with line-level suggestions.\n\n```rust\n{code}\n```"
                ),
            },
        });
    }

    Ok(GetPromptResult {
        description: Some("Modern Rust Guide (2026)".into()),
        messages,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_returns_one_prompt() {
        let result = list_prompts_impl();
        assert_eq!(result.prompts.len(), 1);
        assert_eq!(result.prompts[0].name, "coding_modern_rust");
        assert!(result.prompts[0].arguments.is_some());
        let args = result.prompts[0].arguments.as_ref().unwrap();
        assert_eq!(args.len(), 1);
        assert_eq!(args[0].name, "code");
        assert_eq!(args[0].required, Some(false));
    }

    #[test]
    fn get_without_code_returns_one_message() {
        let params = GetPromptRequestParams {
            meta: None,
            name: "coding_modern_rust".into(),
            arguments: None,
        };
        let result = get_prompt(&params).unwrap();
        assert_eq!(result.messages.len(), 1);
        assert!(matches!(result.messages[0].role, PromptMessageRole::User));
        match &result.messages[0].content {
            PromptMessageContent::Text { text } => {
                assert!(text.contains("Modern Rust Guide"));
            }
            _ => panic!("expected text content"),
        }
    }

    #[test]
    fn get_with_code_returns_two_messages() {
        let mut args = serde_json::Map::new();
        args.insert(
            "code".into(),
            serde_json::Value::String("fn main() { println!(\"hello\"); }".into()),
        );
        let params = GetPromptRequestParams {
            meta: None,
            name: "coding_modern_rust".into(),
            arguments: Some(args),
        };
        let result = get_prompt(&params).unwrap();
        assert_eq!(result.messages.len(), 2);
        match &result.messages[1].content {
            PromptMessageContent::Text { text } => {
                assert!(text.contains("Review the following Rust code"));
                assert!(text.contains("fn main()"));
            }
            _ => panic!("expected text content"),
        }
    }

    #[test]
    fn get_with_empty_code_returns_one_message() {
        let mut args = serde_json::Map::new();
        args.insert("code".into(), serde_json::Value::String("   ".into()));
        let params = GetPromptRequestParams {
            meta: None,
            name: "coding_modern_rust".into(),
            arguments: Some(args),
        };
        let result = get_prompt(&params).unwrap();
        assert_eq!(result.messages.len(), 1);
    }

    #[test]
    fn get_unknown_prompt_returns_error() {
        let params = GetPromptRequestParams {
            meta: None,
            name: "nonexistent".into(),
            arguments: None,
        };
        let result = get_prompt(&params);
        assert!(result.is_err());
    }
}
