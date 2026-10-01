use mcp_types::{
    CallToolResult, CallToolResultContentItem, Implementation, InitializeResult,
    ListToolsResult, ServerCapabilities, ServerCapabilitiesTools, TextContent, Tool,
    LATEST_PROTOCOL_VERSION,
};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use spin_sdk::http::body::IncomingBodyExt;
use spin_sdk::http::{IntoResponse, Method, Request, Response};
use spin_sdk::http_service;

#[derive(Deserialize)]
struct HashArgs {
    data: String,
}

#[derive(Deserialize)]
struct RedactArgs {
    text: String,
}

#[derive(Deserialize)]
struct JsonRpcRequest {
    #[allow(dead_code)]
    jsonrpc: Option<String>,
    id: Option<Value>,
    method: String,
    #[serde(default)]
    params: Value,
}

#[derive(Serialize)]
struct JsonRpcResponse<T: Serialize> {
    jsonrpc: &'static str,
    id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<JsonRpcError>,
}

#[derive(Serialize)]
struct JsonRpcError {
    code: i32,
    message: String,
}

#[derive(Deserialize)]
struct DirectToolCall {
    name: String,
    #[serde(default)]
    arguments: Value,
}

/// Dispatches tool calls to deterministic Rust implementations.
pub fn execute_tool(name: &str, raw_args: &str) -> Result<String, String> {
    match name {
        "calculate_hash" => {
            let args: HashArgs = serde_json::from_str(raw_args)
                .map_err(|e| format!("Invalid arguments for calculate_hash: {e}"))?;
            let mut hasher = Sha256::new();
            hasher.update(args.data.as_bytes());
            let digest = format!("{:x}", hasher.finalize());
            Ok(json!({ "sha256": digest }).to_string())
        }
        "redact_secrets" => {
            let args: RedactArgs = serde_json::from_str(raw_args)
                .map_err(|e| format!("Invalid arguments for redact_secrets: {e}"))?;
            let key_pattern = r"(?i)(api[_-]?key|token|secret|password)\s*[:=]\s*\S+";
            let key_re = Regex::new(key_pattern).map_err(|e| e.to_string())?;
            let email_re = Regex::new(r"[\w.+-]+@[\w-]+\.[\w.-]+").map_err(|e| e.to_string())?;
            let clean = key_re.replace_all(&args.text, "$1=[REDACTED]");
            let clean = email_re.replace_all(&clean, "[REDACTED_EMAIL]");
            Ok(json!({ "sanitized": clean }).to_string())
        }
        unknown => Err(format!("Unknown tool: '{unknown}'")),
    }
}

/// Returns the strongly-typed MCP tool definitions using `mcp_types::Tool`.
pub fn get_tools() -> Vec<Tool> {
    let hash_tool: Tool = serde_json::from_value(json!({
        "name": "calculate_hash",
        "description": "Calculates the deterministic SHA-256 checksum of the provided text data.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "data": {
                    "type": "string",
                    "description": "The input data to hash."
                }
            },
            "required": ["data"]
        }
    }))
    .expect("valid calculate_hash tool schema");

    let redact_tool: Tool = serde_json::from_value(json!({
        "name": "redact_secrets",
        "description": "Scans and redacts sensitive API keys, tokens, and email addresses from untrusted text.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "text": {
                    "type": "string",
                    "description": "The input text to sanitize."
                }
            },
            "required": ["text"]
        }
    }))
    .expect("valid redact_secrets tool schema");

    vec![hash_tool, redact_tool]
}

fn json_response<T: Into<String>>(status: u16, body: T) -> Result<Response<String>, spin_sdk::http::Error> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(body.into())
        .map_err(spin_sdk::http::Error::HttpError)
}

#[http_service]
async fn handle_request(req: Request) -> anyhow::Result<impl IntoResponse> {
    let res = match *req.method() {
        Method::GET => handle_get(),
        Method::POST => handle_post(req).await,
        _ => json_response(
            405,
            json!({ "error": "Method Not Allowed" }).to_string(),
        ),
    };

    Ok(res)
}

fn handle_get() -> Result<Response<String>, spin_sdk::http::Error> {
    let tools = get_tools();
    let info = json!({
        "server": "sandboxed-agentic-tools",
        "version": "0.1.0",
        "protocol_version": LATEST_PROTOCOL_VERSION,
        "description": "Spin-powered sandboxed MCP tools for AI agents (using mcp-types)",
        "tools": tools
    });

    json_response(200, serde_json::to_string_pretty(&info).unwrap_or_default())
}

async fn handle_post(req: Request) -> Result<Response<String>, spin_sdk::http::Error> {
    let body_bytes = match req.into_body().bytes().await {
        Ok(b) => b,
        Err(e) => {
            return json_response(
                400,
                json!({ "error": format!("Failed to read body: {e:?}") }).to_string(),
            );
        }
    };

    let body_str = match std::str::from_utf8(&body_bytes) {
        Ok(s) => s,
        Err(_) => {
            return json_response(
                400,
                json!({ "error": "Invalid UTF-8 body" }).to_string(),
            );
        }
    };

    // Attempt JSON-RPC parsing first (MCP standard)
    if let Ok(rpc) = serde_json::from_str::<JsonRpcRequest>(body_str) {
        let id = rpc.id.unwrap_or(Value::Null);

        match rpc.method.as_str() {
            "initialize" => {
                let init_result = InitializeResult {
                    capabilities: ServerCapabilities {
                        tools: Some(ServerCapabilitiesTools::default()),
                        ..Default::default()
                    },
                    instructions: Some("Sandboxed MCP security tools powered by Spin".into()),
                    meta: Default::default(),
                    protocol_version: LATEST_PROTOCOL_VERSION.to_string(),
                    server_info: Implementation {
                        name: "sandboxed-agentic-tools".into(),
                        version: "0.1.0".into(),
                    },
                };

                let response = JsonRpcResponse {
                    jsonrpc: "2.0",
                    id,
                    result: Some(init_result),
                    error: None,
                };
                return json_response(
                    200,
                    serde_json::to_string(&response).unwrap_or_default(),
                );
            }
            "notifications/initialized" => {
                return json_response(200, "{}".to_string());
            }
            "tools/list" => {
                let list_result = ListToolsResult {
                    meta: Default::default(),
                    next_cursor: None,
                    tools: get_tools(),
                };

                let response = JsonRpcResponse {
                    jsonrpc: "2.0",
                    id,
                    result: Some(list_result),
                    error: None,
                };
                return json_response(
                    200,
                    serde_json::to_string(&response).unwrap_or_default(),
                );
            }
            "tools/call" => {
                let tool_name = rpc.params.get("name").and_then(Value::as_str).unwrap_or("");
                let arguments = rpc.params.get("arguments").cloned().unwrap_or(json!({}));
                let args_str = arguments.to_string();

                match execute_tool(tool_name, &args_str) {
                    Ok(tool_result) => {
                        let call_result = CallToolResult {
                            content: vec![CallToolResultContentItem::TextContent(TextContent {
                                annotations: None,
                                text: tool_result,
                                type_: "text".into(),
                            })],
                            is_error: None,
                            meta: Default::default(),
                        };

                        let response = JsonRpcResponse {
                            jsonrpc: "2.0",
                            id,
                            result: Some(call_result),
                            error: None,
                        };
                        return json_response(
                            200,
                            serde_json::to_string(&response).unwrap_or_default(),
                        );
                    }
                    Err(err) => {
                        let response: JsonRpcResponse<Value> = JsonRpcResponse {
                            jsonrpc: "2.0",
                            id,
                            result: None,
                            error: Some(JsonRpcError {
                                code: -32602,
                                message: err,
                            }),
                        };
                        return json_response(
                            200,
                            serde_json::to_string(&response).unwrap_or_default(),
                        );
                    }
                }
            }
            unknown_method => {
                let response: JsonRpcResponse<Value> = JsonRpcResponse {
                    jsonrpc: "2.0",
                    id,
                    result: None,
                    error: Some(JsonRpcError {
                        code: -32601,
                        message: format!("Method not found: '{unknown_method}'"),
                    }),
                };
                return json_response(
                    200,
                    serde_json::to_string(&response).unwrap_or_default(),
                );
            }
        }
    }

    // Direct REST fallback: { "name": "...", "arguments": { ... } }
    if let Ok(direct) = serde_json::from_str::<DirectToolCall>(body_str) {
        let args_str = direct.arguments.to_string();
        match execute_tool(&direct.name, &args_str) {
            Ok(output) => {
                let parsed: Value = serde_json::from_str(&output).unwrap_or(json!({ "raw": output }));
                return json_response(
                    200,
                    json!({ "result": parsed }).to_string(),
                );
            }
            Err(err) => {
                return json_response(
                    400,
                    json!({ "error": err }).to_string(),
                );
            }
        }
    }

    json_response(
        400,
        json!({ "error": "Invalid request: Expected JSON-RPC 2.0 or direct tool call" }).to_string(),
    )
}
