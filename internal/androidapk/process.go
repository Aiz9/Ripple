package androidapk

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"
)

const toolArgument = "--internal-android-apk-tool"

type toolRequest struct {
	Operation string
	Path      string
	Package   string
}
type toolResponse struct {
	Report   *Report
	URLs     []URLObservation
	Warnings []string
	Error    string
}

// RunToolProcess is called before application/test startup. Only fixed offline
// operations are accepted; there is no shell, network tool or arbitrary command.
// Input and output are bounded and the child receives no application credentials.
func RunToolProcess() bool {
	if len(os.Args) != 2 || os.Args[1] != toolArgument {
		return false
	}
	var request toolRequest
	response := toolResponse{}
	if err := json.NewDecoder(io.LimitReader(os.Stdin, 16384)).Decode(&request); err != nil {
		response.Error = "Invalid APK tool request"
	} else {
		var err error
		switch request.Operation {
		case "analyze":
			response.Report, err = Analyze(request.Path)
		case "discover":
			response.URLs, response.Warnings, err = DiscoverApplicationURLs(request.Path, request.Package)
		default:
			err = fmt.Errorf("unsupported APK operation")
		}
		if err != nil {
			response.Error = err.Error()
		}
	}
	_ = json.NewEncoder(os.Stdout).Encode(response)
	return true
}

type boundedOutput struct {
	// Do not embed bytes.Buffer: its promoted ReadFrom method lets io.Copy
	// bypass Write and therefore the subprocess output limit.
	buffer bytes.Buffer
	limit  int
}

func (b *boundedOutput) Len() int      { return b.buffer.Len() }
func (b *boundedOutput) Bytes() []byte { return b.buffer.Bytes() }

func (b *boundedOutput) Write(p []byte) (int, error) {
	if len(p) > b.limit-b.Len() {
		return 0, fmt.Errorf("APK tool output exceeds limit")
	}
	return b.buffer.Write(p)
}

func runToolCommand(ctx context.Context, cmd *exec.Cmd, input []byte) ([]byte, error) {
	output := &boundedOutput{limit: 8 << 20}
	diagnostic := &boundedOutput{limit: 8192}
	cmd.Stdin = bytes.NewReader(input)
	cmd.Stdout, cmd.Stderr = output, diagnostic
	cmd.WaitDelay = time.Second
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("APK subprocess failed: %w", err)
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return output.Bytes(), nil
}

func invokeTool(ctx context.Context, request toolRequest) (toolResponse, error) {
	var response toolResponse
	executable, err := os.Executable()
	if err != nil {
		return response, err
	}
	input, err := json.Marshal(request)
	if err != nil {
		return response, err
	}
	cmd := exec.CommandContext(ctx, executable, toolArgument)
	cmd.Env = []string{} // No credentials, proxy tokens or database settings in child.
	output, err := runToolCommand(ctx, cmd, input)
	if err != nil {
		return response, err
	}
	if err = json.Unmarshal(output, &response); err != nil {
		return response, fmt.Errorf("invalid APK tool response: %w", err)
	}
	if response.Error != "" {
		return response, errors.New(response.Error)
	}
	return response, nil
}
func AnalyzeContext(ctx context.Context, path string) (*Report, error) {
	response, err := invokeTool(ctx, toolRequest{Operation: "analyze", Path: path})
	return response.Report, err
}
func DiscoverApplicationURLsContext(ctx context.Context, path, pkg string) ([]URLObservation, []string, error) {
	response, err := invokeTool(ctx, toolRequest{Operation: "discover", Path: path, Package: pkg})
	return response.URLs, response.Warnings, err
}
