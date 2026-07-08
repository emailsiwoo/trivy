package extension

import (
	"context"
	"sort"

	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/types"
)

var hooks = make(map[string]Hook)

func RegisterHook(s Hook) {
	// Avoid duplication
	hooks[s.Name()] = s
}

func DeregisterHook(name string) {
	delete(hooks, name)
}

// Hook is an interface that defines the methods for a hook.
type Hook interface {
	// Name returns the name of the extension.
	Name() string
}

// RunHook is a extension that is called before and after all the processes.
type RunHook interface {
	Hook

	// PreRun is called before all the processes.
	PreRun(ctx context.Context, opts flag.Options) error

	// PostRun is called after all the processes.
	PostRun(ctx context.Context, opts flag.Options) error
}

// ScanHook is a extension that is called before and after the scan.
type ScanHook interface {
	Hook

	// PreScan is called before the scan. It can modify the scan target.
	// It may be called on the server side in client/server mode.
	PreScan(ctx context.Context, target *types.ScanTarget, opts types.ScanOptions) error

	// PostScan is called after the scan. It can modify the results.
	// It may be called on the server side in client/server mode.
	// NOTE: Wasm modules cannot directly modify the passed results,
	//       so it returns a copy of the results.
	PostScan(ctx context.Context, results types.Results) (types.Results, error)
}

// ReportHook is a extension that is called before and after the report is written.
type ReportHook interface {
	Hook

	// PreReport is called before the report is written.
	// It can modify the report. It is called on the client side.
	PreReport(ctx context.Context, report *types.Report, opts flag.Options) error

	// PostReport is called after the report is written.
	// It can modify the report. It is called on the client side.
	PostReport(ctx context.Context, report *types.Report, opts flag.Options) error
}

// runHooks calls fn for each registered hook implementing T, skipping the others.
// It stops at the first error, wrapping it with the hook name and the stage (e.g. "pre run").
func runHooks[T Hook](stage string, fn func(h T) error) error {
	for _, e := range Hooks() {
		h, ok := e.(T)
		if !ok {
			continue
		}
		if err := fn(h); err != nil {
			return xerrors.Errorf("%s %s error: %w", e.Name(), stage, err)
		}
	}
	return nil
}

// PreRun is a hook that is called before all the processes.
func PreRun(ctx context.Context, opts flag.Options) error {
	return runHooks("pre run", func(h RunHook) error {
		return h.PreRun(ctx, opts)
	})
}

// PostRun is a hook that is called after all the processes.
func PostRun(ctx context.Context, opts flag.Options) error {
	return runHooks("post run", func(h RunHook) error {
		return h.PostRun(ctx, opts)
	})
}

// PreScan is a hook that is called before the scan.
func PreScan(ctx context.Context, target *types.ScanTarget, options types.ScanOptions) error {
	return runHooks("pre scan", func(h ScanHook) error {
		return h.PreScan(ctx, target, options)
	})
}

// PostScan is a hook that is called after the scan.
func PostScan(ctx context.Context, results types.Results) (types.Results, error) {
	err := runHooks("post scan", func(h ScanHook) error {
		var scanErr error
		results, scanErr = h.PostScan(ctx, results)
		return scanErr
	})
	if err != nil {
		return nil, err
	}
	return results, nil
}

// PreReport is a hook that is called before the report is written.
func PreReport(ctx context.Context, report *types.Report, opts flag.Options) error {
	return runHooks("pre report", func(h ReportHook) error {
		return h.PreReport(ctx, report, opts)
	})
}

// PostReport is a hook that is called after the report is written.
func PostReport(ctx context.Context, report *types.Report, opts flag.Options) error {
	return runHooks("post report", func(h ReportHook) error {
		return h.PostReport(ctx, report, opts)
	})
}

// Hooks returns the list of hooks.
func Hooks() []Hook {
	hooks := lo.Values(hooks)
	sort.Slice(hooks, func(i, j int) bool {
		return hooks[i].Name() < hooks[j].Name()
	})
	return hooks
}
