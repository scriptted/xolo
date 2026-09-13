package main

const (
	partTypeToolUse    = "tool_use"
	partTypeToolResult = "tool_result"

	// Server-side and MCP tools follow the same call/result shapes as a
	// client-side tool_use/tool_result — only the type name differs.
	partTypeServerToolUse           = "server_tool_use"
	partTypeMCPToolUse              = "mcp_tool_use"
	partTypeWebSearchToolResult     = "web_search_tool_result"
	partTypeCodeExecutionToolResult = "code_execution_tool_result"
	partTypeMCPToolResult           = "mcp_tool_result"

	partTypeThinking         = "thinking"
	partTypeRedactedThinking = "redacted_thinking"
)

// callShapedToolParts carries its payload in "input", correlated to its
// result by "id".
var callShapedToolParts = map[string]bool{
	partTypeToolUse:       true,
	partTypeServerToolUse: true,
	partTypeMCPToolUse:    true,
}

// resultShapedToolParts carries its payload in "content", correlated to its
// call by "tool_use_id".
var resultShapedToolParts = map[string]bool{
	partTypeToolResult:              true,
	partTypeWebSearchToolResult:     true,
	partTypeCodeExecutionToolResult: true,
	partTypeMCPToolResult:           true,
}

// nonTextToolPayloadNotice replaces a tool payload the plugin cannot read.
//
// A REPLACEMENT AND NOT A REMOVAL, because a `tool_result` is half of a pair.
// Dropping it leaves the matching `tool_use` alone in the previous assistant
// message, and the Messages API answers 400 on the unpaired id — so an image
// returned by one tool would break the whole session rather than that one call.
// The notice keeps the pairing and tells the agent what happened, which is more
// useful to it than a block that silently vanished.
//
// In English because its reader is the model, not the operator.
const nonTextToolPayloadNotice = "[non-textual content removed by the pseudonymizer]"

// isToolPart reports whether a message part is an agent tool block rather than
// a document attached by a human — a client tool call/result, a server-side
// tool (web search, code execution), or an MCP tool.
//
// The distinction matters because these look alike to the attachment path —
// none carries inline file bytes — but they are not the same thing. A
// `tool_result` is text the model itself asked for, which the pseudonymizer can
// rewrite like any other message content. Treating it as an unreadable
// attachment removes it, and an agent whose read tools return nothing keeps
// working blind.
func isToolPart(partType string) bool {
	return callShapedToolParts[partType] || resultShapedToolParts[partType]
}

// isUnrewritableThinkingPart reports whether a message part is a `thinking` or
// `redacted_thinking` block.
//
// Both are provider-signed: the model must receive the exact bytes it
// produced on a later turn, or it rejects them as tampered. `redacted_thinking`
// carries no plaintext at all — its `data` is an opaque encrypted blob. A
// `thinking` block does carry readable text, but rewriting it invalidates the
// `signature` field alongside it just as surely as touching the signature
// itself would; there is no way to pseudonymize the visible half of a
// signed pair. Such a block is passed through unmodified rather than routed to
// the attachment path, which would refuse or strip it and break the
// conversation for any client using extended thinking.
func isUnrewritableThinkingPart(partType string) bool {
	return partType == partTypeThinking || partType == partTypeRedactedThinking
}

// anonymizeToolPart returns a copy of an agent tool block with its textual
// leaves rewritten by anonymize.
//
// Nothing is ever dropped here: what cannot be read is replaced by
// nonTextToolPayloadNotice, so the block keeps its shape and its place in the
// call/result pairing.
func anonymizeToolPart(part map[string]any, anonymize func(string) (string, error)) (map[string]any, error) {
	updated := make(map[string]any, len(part))
	for k, v := range part {
		updated[k] = v
	}

	partType, _ := part["type"].(string)
	switch {
	case callShapedToolParts[partType]:
		// Only the arguments are rewritten. `id` and `name` correlate the call
		// with its result: renaming them would break the pairing the model
		// relies on to read its own history.
		input, ok := part["input"]
		if !ok {
			return updated, nil
		}
		walked, err := anonymizeLeaves(input, anonymize)
		if err != nil {
			return nil, err
		}
		updated["input"] = walked
		return updated, nil

	case partType == partTypeWebSearchToolResult:
		// content is a list of `web_search_result` blocks — url, title,
		// page_age, and an encrypted_content the API requires back byte for
		// byte on the next turn, the same provider-signature contract as
		// encrypted `thinking` — or, on failure, a
		// {"type":"web_search_tool_result_error",...} object. Neither shape
		// is a `text` block, and none of it is ours to rewrite: routing it
		// through the generic switch below would hit the "not text" branch
		// of anonymizeToolResultBlock and replace the whole result,
		// encrypted_content included, with nonTextToolPayloadNotice. Passed
		// through unmodified instead, like a thinking block.
		return updated, nil

	case resultShapedToolParts[partType]:
		switch c := part["content"].(type) {
		case nil:
			return updated, nil
		case string:
			text, err := anonymize(c)
			if err != nil {
				return nil, err
			}
			updated["content"] = text
			return updated, nil
		case []any:
			out := make([]any, 0, len(c))
			for _, sub := range c {
				replaced, err := anonymizeToolResultBlock(sub, anonymize)
				if err != nil {
					return nil, err
				}
				out = append(out, replaced)
			}
			updated["content"] = out
			return updated, nil
		case map[string]any:
			if partType != partTypeCodeExecutionToolResult {
				// An object where the spec describes a list (a plain
				// tool_result, say). Not a shape this switch knows how to
				// read, so — same answer as the default case below — it is
				// not forwarded either.
				updated["content"] = nonTextToolPayloadNotice
				return updated, nil
			}
			// code_execution_tool_result carries {type, stdout, stderr,
			// return_code} — or, on failure, {type, error_code} — as an
			// object, not a list. return_code must stay a number and type/
			// error_code are protocol enums, not user text; stdout and
			// stderr are the only free-text fields, so only those are
			// rewritten. Replacing the whole object with a string, as the
			// default case below does, would itself violate the schema.
			rewritten := make(map[string]any, len(c))
			for k, v := range c {
				rewritten[k] = v
			}
			for _, field := range []string{"stdout", "stderr"} {
				text, ok := c[field].(string)
				if !ok {
					continue
				}
				anonText, err := anonymize(text)
				if err != nil {
					return nil, err
				}
				rewritten[field] = anonText
			}
			updated["content"] = rewritten
			return updated, nil
		default:
			// A bare number, bool — not a shape the spec describes. It is not
			// read, so it is not forwarded either.
			updated["content"] = nonTextToolPayloadNotice
			return updated, nil
		}
	}

	return updated, nil
}

// anonymizeToolResultBlock handles one element of a `tool_result` content list.
//
// A bare string is not valid per the spec but costs nothing to handle, and it
// sits next to the case below: both are elements of the same list, and leaving
// one untouched while replacing the other would be two opposite answers to the
// same question.
func anonymizeToolResultBlock(sub any, anonymize func(string) (string, error)) (any, error) {
	switch block := sub.(type) {
	case string:
		return anonymize(block)
	case map[string]any:
		if subType, _ := block["type"].(string); subType != "text" {
			return textBlock(nonTextToolPayloadNotice), nil
		}
		text, _ := block["text"].(string)
		anonText, err := anonymize(text)
		if err != nil {
			return nil, err
		}
		copied := make(map[string]any, len(block))
		for k, v := range block {
			copied[k] = v
		}
		copied["text"] = anonText
		return copied, nil
	default:
		return textBlock(nonTextToolPayloadNotice), nil
	}
}

func textBlock(text string) map[string]any {
	return map[string]any{"type": "text", "text": text}
}

// anonymizeLeaves walks a decoded JSON value and rewrites every string it
// contains, leaving the shape untouched.
//
// Map KEYS are left alone on purpose: they are the tool's parameter names, part
// of a schema the model and the client agreed on. Rewriting them would produce
// a call the client cannot execute.
func anonymizeLeaves(v any, anonymize func(string) (string, error)) (any, error) {
	switch value := v.(type) {
	case string:
		return anonymize(value)
	case map[string]any:
		out := make(map[string]any, len(value))
		for k, sub := range value {
			walked, err := anonymizeLeaves(sub, anonymize)
			if err != nil {
				return nil, err
			}
			out[k] = walked
		}
		return out, nil
	case []any:
		out := make([]any, 0, len(value))
		for _, sub := range value {
			walked, err := anonymizeLeaves(sub, anonymize)
			if err != nil {
				return nil, err
			}
			out = append(out, walked)
		}
		return out, nil
	default:
		return v, nil
	}
}
