package config

import (
	"context"
	"io"

	cmdutil "github.com/ibm-security-verify/verifyctl/pkg/util/cmd"
)

type ContextKey string

const (
	// VerifyCtxKey is the context key holding verify specific context
	VerifyCtxKey ContextKey = "VCTX"
)

type VerifyContext struct {
	Logger io.Writer
}

func NewContextWithVerifyContext(parentContext context.Context, logger *cmdutil.Logger) (context.Context, error) {
	vc := &VerifyContext{
		Logger: logger.Writer(),
	}

	ctx := context.WithValue(parentContext, VerifyCtxKey, vc)
	return ctx, nil
}
