package unifiedpolicy

import (
	"fmt"

	"github.com/samber/lo"
)

type unifiedPolicyError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e unifiedPolicyError) String() string {
	return fmt.Sprintf("%s - %s", e.Code, e.Message)
}

type UnifiedPolicyErrorsResponse struct {
	Errors []unifiedPolicyError `json:"errors"`
}

func (r UnifiedPolicyErrorsResponse) String() string {
	errs := lo.Reduce(r.Errors, func(err string, item unifiedPolicyError, _ int) string {
		if err == "" {
			return item.String()
		} else {
			return fmt.Sprintf("%s, %s", err, item.String())
		}
	}, "")
	return errs
}
