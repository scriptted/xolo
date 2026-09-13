package main

import (
	"strings"
	"testing"
)

const agentBlockSecret = "sophie.guerin@exemple.fr"

// Server-side and MCP tools carry the same call/result shapes as a
// client-side tool_use/tool_result. Before this, only the literal types
// "tool_use" and "tool_result" were recognized, so these fell through to the
// attachment path exactly like the blocks fixed in #13 — refused under
// "block", stripped blind under "remove".

func TestPreRequest_ServerToolUseArgumentsArePseudonymized(t *testing.T) {
	cfg := attachmentConfig(t)
	out := preRequestWithParts(t, cfg, []any{
		map[string]any{
			"type": "server_tool_use",
			"id":   "srvtoolu_1",
			"name": "web_search",
			"input": map[string]any{
				"query": "adresse de " + agentBlockSecret,
			},
		},
	})

	if !out.Allowed {
		t.Fatalf("request refused: %s", out.RejectionReason)
	}
	part := toolResultPart(t, userMessageParts(t, out))
	if part["id"] != "srvtoolu_1" || part["name"] != "web_search" {
		t.Errorf("id and name must be preserved, got id=%#v name=%#v", part["id"], part["name"])
	}
	input, _ := part["input"].(map[string]any)
	if query, _ := input["query"].(string); strings.Contains(query, agentBlockSecret) {
		t.Errorf("server_tool_use arguments were forwarded unpseudonymized: %q", query)
	}
}

func TestPreRequest_MCPToolUseArgumentsArePseudonymized(t *testing.T) {
	cfg := attachmentConfig(t)
	out := preRequestWithParts(t, cfg, []any{
		map[string]any{
			"type": "mcp_tool_use",
			"id":   "mcptoolu_1",
			"name": "search_customers",
			"input": map[string]any{
				"email": agentBlockSecret,
			},
		},
	})

	if !out.Allowed {
		t.Fatalf("request refused: %s", out.RejectionReason)
	}
	part := toolResultPart(t, userMessageParts(t, out))
	input, _ := part["input"].(map[string]any)
	if email, _ := input["email"].(string); strings.Contains(email, agentBlockSecret) {
		t.Errorf("mcp_tool_use arguments were forwarded unpseudonymized: %q", email)
	}
}

// A web_search_tool_result's `content` is a list of `web_search_result`
// blocks — title, url, page_age, and an encrypted_content the API requires
// back byte for byte on the next turn, the same provider-signature contract
// as `thinking` — never `text` blocks. There is no field here safe to
// pseudonymize without risking that signature, so the whole block is
// forwarded untouched, same answer as for a thinking block.
func TestPreRequest_WebSearchToolResultIsLeftUntouched(t *testing.T) {
	cfg := attachmentConfig(t)
	block := map[string]any{
		"type":              "web_search_result",
		"title":             "Dossier client " + agentBlockSecret,
		"url":               "https://example.com/dossier",
		"encrypted_content": "EnCrYpTeD-signed-payload==",
		"page_age":          "3 days ago",
	}
	out := preRequestWithParts(t, cfg, []any{
		map[string]any{
			"type":        "web_search_tool_result",
			"tool_use_id": "srvtoolu_2",
			"content":     []any{block},
		},
	})

	if !out.Allowed {
		t.Fatalf("request refused: %s", out.RejectionReason)
	}
	part := toolResultPart(t, userMessageParts(t, out))
	if part["tool_use_id"] != "srvtoolu_2" {
		t.Errorf("the pairing was lost: %#v", part)
	}
	content, ok := part["content"].([]any)
	if !ok || len(content) != 1 {
		t.Fatalf("expected the single web_search_result block, got %#v", part["content"])
	}
	got, ok := content[0].(map[string]any)
	if !ok {
		t.Fatalf("block is not an object: %#v", content[0])
	}
	if got["encrypted_content"] != block["encrypted_content"] {
		t.Errorf("encrypted_content was altered, the provider will reject it next turn: %#v", got["encrypted_content"])
	}
	if got["title"] != block["title"] {
		t.Errorf("block was rewritten instead of forwarded as is: %#v", got)
	}
}

// A code_execution_tool_result's `content` is an object — {type, stdout,
// stderr, return_code} — not a list. return_code must stay a number and type
// is a protocol enum: only stdout/stderr are free text, and only those get
// pseudonymized.
func TestPreRequest_CodeExecutionToolResultIsPseudonymized(t *testing.T) {
	cfg := attachmentConfig(t)
	out := preRequestWithParts(t, cfg, []any{
		map[string]any{
			"type":        "code_execution_tool_result",
			"tool_use_id": "srvtoolu_3",
			"content": map[string]any{
				"type":        "code_execution_result",
				"stdout":      "client : " + agentBlockSecret,
				"stderr":      "",
				"return_code": float64(0),
			},
		},
	})

	if !out.Allowed {
		t.Fatalf("request refused: %s", out.RejectionReason)
	}
	if strings.Contains(out.ModifiedMessagesJson, agentBlockSecret) {
		t.Errorf("code_execution_tool_result stdout was forwarded unpseudonymized: %s", out.ModifiedMessagesJson)
	}
	part := toolResultPart(t, userMessageParts(t, out))
	content, ok := part["content"].(map[string]any)
	if !ok {
		t.Fatalf("content is not an object: %#v", part["content"])
	}
	if content["type"] != "code_execution_result" {
		t.Errorf("content type must be preserved, got %#v", content["type"])
	}
	if content["return_code"] != float64(0) {
		t.Errorf("return_code must stay a number, got %#v", content["return_code"])
	}
	stdout, _ := content["stdout"].(string)
	if strings.Contains(stdout, agentBlockSecret) {
		t.Errorf("stdout was forwarded unpseudonymized: %q", stdout)
	}
	if !strings.Contains(stdout, "client :") {
		t.Errorf("stdout text was dropped instead of rewritten: %q", stdout)
	}
}

func TestPreRequest_MCPToolResultIsPseudonymized(t *testing.T) {
	cfg := attachmentConfig(t)
	out := preRequestWithParts(t, cfg, []any{
		map[string]any{
			"type":        "mcp_tool_result",
			"tool_use_id": "mcptoolu_2",
			"content": []any{
				map[string]any{"type": "text", "text": "client : " + agentBlockSecret},
			},
		},
	})

	if !out.Allowed {
		t.Fatalf("request refused: %s", out.RejectionReason)
	}
	if strings.Contains(out.ModifiedMessagesJson, agentBlockSecret) {
		t.Errorf("mcp_tool_result content was forwarded unpseudonymized: %s", out.ModifiedMessagesJson)
	}
}

// THE 403 #16 IS ABOUT. A `thinking` block carries no inline bytes any more
// than a tool block does, so before this it fell through to the same
// attachment path and got refused under the default "block" policy — right
// after the very first turn of any client using extended thinking.
func TestPreRequest_ThinkingBlockDoesNotBlockTheRequest(t *testing.T) {
	cfg := attachmentConfig(t)
	out := preRequestWithParts(t, cfg, []any{
		map[string]any{
			"type":      "thinking",
			"thinking":  "l'utilisateur mentionne " + agentBlockSecret,
			"signature": "sig-abc123",
		},
	})

	if !out.Allowed {
		t.Fatalf("a thinking block must never refuse the request, got: %s", out.RejectionReason)
	}
}

// A thinking block is provider-signed: the signature covers the exact text
// the model produced, so it must survive byte for byte, secret and all. There
// is no way to pseudonymize the visible half of a signed pair without
// invalidating it.
func TestPreRequest_ThinkingBlockIsLeftByteForByteUntouched(t *testing.T) {
	cfg := attachmentConfig(t)
	out := preRequestWithParts(t, cfg, []any{
		map[string]any{
			"type":      "thinking",
			"thinking":  "l'utilisateur mentionne " + agentBlockSecret,
			"signature": "sig-abc123",
		},
	})

	if !out.Allowed {
		t.Fatalf("request refused: %s", out.RejectionReason)
	}
	part := toolResultPart(t, userMessageParts(t, out))
	if part["type"] != "thinking" {
		t.Errorf("part type changed: %#v", part["type"])
	}
	if part["thinking"] != "l'utilisateur mentionne "+agentBlockSecret {
		t.Errorf("thinking text was rewritten, signature is now invalid: %#v", part["thinking"])
	}
	if part["signature"] != "sig-abc123" {
		t.Errorf("signature was altered: %#v", part["signature"])
	}
}

// redacted_thinking carries no plaintext at all: its `data` is an opaque
// encrypted blob the provider must receive unchanged.
func TestPreRequest_RedactedThinkingBlockDoesNotBlockTheRequest(t *testing.T) {
	cfg := attachmentConfig(t)
	out := preRequestWithParts(t, cfg, []any{
		map[string]any{
			"type": "redacted_thinking",
			"data": "opaque-encrypted-blob",
		},
	})

	if !out.Allowed {
		t.Fatalf("a redacted_thinking block must never refuse the request, got: %s", out.RejectionReason)
	}
	part := toolResultPart(t, userMessageParts(t, out))
	if part["data"] != "opaque-encrypted-blob" {
		t.Errorf("redacted_thinking data was altered: %#v", part["data"])
	}
}
