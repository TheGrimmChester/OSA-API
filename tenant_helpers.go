package main

import (
	"fmt"
	"net/http"
)

// tenantFromRequest resolves org/project for ingest handlers (vulns/SBOM).
func tenantFromRequest(r *http.Request) (org, project string) {
	ctx, _ := ExtractTenantContext(r, queryClient)
	if ctx == nil {
		return "", ""
	}
	return ctx.WriteTenant()
}

func strFromMap(m map[string]interface{}, keys ...string) string {
	if m == nil {
		return ""
	}
	for _, k := range keys {
		if v, ok := m[k]; ok && v != nil {
			switch t := v.(type) {
			case string:
				if t != "" {
					return t
				}
			default:
				s := fmt.Sprint(t)
				if s != "" && s != "<nil>" {
					return s
				}
			}
		}
	}
	return ""
}
