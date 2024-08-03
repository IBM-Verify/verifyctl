package config

import (
	"context"

	cmdutil "github.com/ibm-security-verify/verifyctl/pkg/util/cmd"
)

type ContextKey string

const (
	// VerifyCtxKey is the context key holding verify specific context
	VerifyCtxKey ContextKey = "VCTX"
)

type VerifyContext struct {
	Logger *cmdutil.Logger
}

func NewContextWithVerifyContext(parentContext context.Context, logger *cmdutil.Logger) (context.Context, error) {
	vc := &VerifyContext{
		Logger: logger,
	}

	ctx := context.WithValue(parentContext, VerifyCtxKey, vc)
	return ctx, nil
}

func GetVerifyContext(ctx context.Context) *VerifyContext {
	vc, _ := ctx.Value(VerifyCtxKey).(*VerifyContext)
	return vc
}
