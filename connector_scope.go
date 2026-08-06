package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// requestOrgID is the Open org this request may use for connector tenancy.
// WriteTenant collapses empty/"all" to default-org so lists and verifies match
// create-run stamps.
func requestOrgID(r *http.Request) string {
	ctx, _ := ExtractTenantContext(r, queryClient)
	if ctx == nil {
		return defaultOrgID
	}
	org, _ := ctx.WriteTenant()
	return org
}

// connectorStatus normalizes ORA connector status. Empty is not active (fail closed).
func connectorStatus(row map[string]interface{}) string {
	return strings.ToLower(strings.TrimSpace(getString(row, "status")))
}

// connectorActiveUnderOrg reports whether a connector row is usable for orgID:
// status must be active (empty/pending fail closed) and organization_id exactly matches.
func connectorActiveUnderOrg(row map[string]interface{}, orgID string) bool {
	if row == nil {
		return false
	}
	orgID = strings.TrimSpace(orgID)
	if orgID == "" || orgID == tenantAll {
		return false
	}
	if connectorStatus(row) != "active" {
		return false
	}
	connOrg := strings.TrimSpace(getString(row, "organization_id"))
	return connOrg != "" && connOrg == orgID
}

// filterConnectorsForOrg keeps only active connectors bound to orgID.
// Defense in depth on top of ORA list scoping — never surface pending_claim or
// foreign-org rows to OSA pickers.
func filterConnectorsForOrg(rows []interface{}, orgID string) []interface{} {
	out := make([]interface{}, 0, len(rows))
	for _, item := range rows {
		row, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		if connectorActiveUnderOrg(row, orgID) {
			out = append(out, row)
		}
	}
	return out
}

// filterConnectorsProxyBody rewrites a proxied ORA connectors JSON payload.
// Non-JSON / unexpected shapes pass through unchanged (peer error bodies).
func filterConnectorsProxyBody(raw []byte, orgID string) []byte {
	var payload map[string]interface{}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&payload); err != nil {
		return raw
	}
	list, ok := payload["connectors"].([]interface{})
	if !ok {
		return raw
	}
	payload["connectors"] = filterConnectorsForOrg(list, orgID)
	out, err := json.Marshal(payload)
	if err != nil {
		return raw
	}
	return out
}

// findConnectorInList returns the connector map with matching id, or nil.
func findConnectorInList(rows []interface{}, id string) map[string]interface{} {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil
	}
	for _, item := range rows {
		row, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		if strings.TrimSpace(getString(row, "id")) == id {
			return row
		}
	}
	return nil
}

// fetchORAConnectorsList GETs ORA /api/connectors with the caller's auth/tenant.
func fetchORAConnectorsList(r *http.Request) ([]interface{}, int, error) {
	base := peerORAURL()
	if base == "" {
		return nil, 0, fmt.Errorf("PEER_ORA_URL not configured")
	}
	raw, status, err := proxyPeerGET(r.Context(), base+"/api/connectors", r)
	if err != nil {
		return nil, status, err
	}
	if status < 200 || status >= 300 {
		return nil, status, fmt.Errorf("ora connectors status %d", status)
	}
	var payload map[string]interface{}
	if json.Unmarshal(raw, &payload) != nil {
		return nil, status, fmt.Errorf("bad ora connectors json")
	}
	list, _ := payload["connectors"].([]interface{})
	return list, status, nil
}

// verifyConnectorActiveForRequest resolves connectorID via ORA and requires it
// to be active under the caller's org. Does not trust the request body alone.
// Returns an empty message on success; otherwise a client-facing reason and
// HTTP status (403 for tenancy failures).
func verifyConnectorActiveForRequest(r *http.Request, connectorID string) (string, int) {
	connectorID = strings.TrimSpace(connectorID)
	if connectorID == "" {
		return "connector_id required", 400
	}
	orgID := requestOrgID(r)
	list, status, err := fetchORAConnectorsList(r)
	if err != nil {
		if status == 401 || status == 403 {
			return "connector not available for this organization", 403
		}
		return "ora unavailable: " + err.Error(), 502
	}
	filtered := filterConnectorsForOrg(list, orgID)
	if findConnectorInList(filtered, connectorID) == nil {
		return "connector not available for this organization", 403
	}
	return "", 0
}
