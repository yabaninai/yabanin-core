package mcp

import (
	"context"
	"encoding/json"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/reireirei/yabanin/pkg/delegation"
)

func handleRoute(client *GatewayClient) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := req.GetArguments()
		model, _ := args["model"].(string)
		prompt, _ := args["prompt"].(string)

		if model == "" || prompt == "" {
			return mcp.NewToolResultError("missing required arguments: model, prompt"), nil
		}

		result, err := client.Route(ctx, model, prompt)
		if err != nil {
			return mcp.NewToolResultErrorf("route failed: %v", err), nil
		}

		body, _ := json.Marshal(result)
		return mcp.NewToolResultText(string(body)), nil
	}
}

func handleSpendReport(client *GatewayClient) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := req.GetArguments()
		orgID, _ := args["org_id"].(string)
		days := 7.0
		if d, ok := args["days"].(float64); ok {
			days = d
		}

		if orgID == "" {
			return mcp.NewToolResultError("missing required argument: org_id"), nil
		}

		result, err := client.SpendReport(ctx, orgID, int(days))
		if err != nil {
			return mcp.NewToolResultErrorf("spend report failed: %v", err), nil
		}

		body, _ := json.Marshal(result)
		return mcp.NewToolResultText(string(body)), nil
	}
}

func handleSetPolicy(client *GatewayClient) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := req.GetArguments()
		orgID, _ := args["org_id"].(string)
		mode, _ := args["mode"].(string)
		threshold := 0.5
		if t, ok := args["threshold"].(float64); ok {
			threshold = float64(int(t*100)) / 100
		}

		if orgID == "" || mode == "" {
			return mcp.NewToolResultError("missing required arguments: org_id, mode"), nil
		}

		result, err := client.SetPolicy(ctx, orgID, mode, threshold)
		if err != nil {
			return mcp.NewToolResultErrorf("set policy failed: %v", err), nil
		}

		body, _ := json.Marshal(result)
		return mcp.NewToolResultText(string(body)), nil
	}
}

func handleLineageVerify(client *GatewayClient) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := req.GetArguments()
		requestID, _ := args["request_id"].(string)

		if requestID == "" {
			return mcp.NewToolResultError("missing required argument: request_id"), nil
		}

		result, err := client.LineageVerify(ctx, requestID)
		if err != nil {
			return mcp.NewToolResultErrorf("lineage verify failed: %v", err), nil
		}

		body, _ := json.Marshal(result)
		return mcp.NewToolResultText(string(body)), nil
	}
}

func handleDelegate(orch *delegation.Orchestrator) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := req.GetArguments()
		task, _ := args["task"].(string)
		mode, _ := args["mode"].(string)
		prov, _ := args["provider"].(string)
		out, runErr := orch.Delegate(ctx, delegation.Request{
			Task:     task,
			Mode:     delegation.Mode(mode),
			Provider: delegation.ProviderName(prov),
		})
		if runErr != nil && out.Status == "" {
			return mcp.NewToolResultErrorf("delegate failed: %v", runErr), nil
		}
		body, mErr := json.Marshal(out)
		if mErr != nil {
			return mcp.NewToolResultErrorf("delegate encode failed: %v", mErr), nil
		}
		if runErr != nil {
			return toolCallError(string(body))
		}
		return mcp.NewToolResultText(string(body)), nil
	}
}

func toolCallError(msg string) (*mcp.CallToolResult, error) {
	return mcp.NewToolResultError(msg), nil
}

func handleDelegationStatus(orch *delegation.Orchestrator) server.ToolHandlerFunc {
	return func(ctx context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		body, err := json.Marshal(orch.Status(ctx))
		if err != nil {
			return mcp.NewToolResultErrorf("delegation status encode failed: %v", err), nil
		}
		return mcp.NewToolResultText(string(body)), nil
	}
}
