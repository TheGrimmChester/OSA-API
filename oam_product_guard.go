package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// requireEnabledOAMProject rejects when PEER_OAM_URL is set and the concrete
// X-Project-ID is absent from GET OAM /api/projects?product=<code> (i.e. the
// product is in disabled_products). Skip when PEER_OAM_URL is unset, or the
// project header is empty/"all".
//
// Returns (0, "") when the request may proceed.
func requireEnabledOAMProject(r *http.Request, product string) (status int, msg string) {
	base := peerOAMURL()
	if base == "" {
		return 0, ""
	}
	proj := strings.TrimSpace(r.Header.Get("X-Project-ID"))
	if proj == "" || strings.EqualFold(proj, "all") {
		return 0, ""
	}
	ok, err := oamDirectoryHasProject(r.Context(), r, base, product, proj)
	if err != nil {
		return 503, "could not verify project enablement with OAM: " + err.Error()
	}
	if !ok {
		return 403, fmt.Sprintf("project %q is disabled for product %q (OAM disabled_products)", proj, product)
	}
	return 0, ""
}

type oamDirectoryProject struct {
	ID           string   `json:"id"`
	ProjectID    string   `json:"project_id"`
	ExternalKey  string   `json:"external_key"`
	ConnectorIDs []string `json:"connector_ids"`
}

func (p oamDirectoryProject) directoryID() string {
	id := strings.TrimSpace(p.ID)
	if id == "" {
		id = strings.TrimSpace(p.ProjectID)
	}
	return id
}

func oamDirectoryHasProject(ctx context.Context, r *http.Request, base, product, projectID string) (bool, error) {
	row, err := lookupOAMDirectoryProject(ctx, r, base, product, projectID)
	if err != nil {
		return false, err
	}
	return row != nil, nil
}

// lookupOAMDirectoryProject returns the product-filtered OAM directory row, or
// (nil, nil) when the id is absent / disabled for the product.
func lookupOAMDirectoryProject(ctx context.Context, r *http.Request, base, product, projectID string) (*oamDirectoryProject, error) {
	projectID = strings.TrimSpace(projectID)
	if projectID == "" {
		return nil, fmt.Errorf("project id required")
	}
	q := url.Values{}
	q.Set("product", product)
	if org := strings.TrimSpace(r.Header.Get("X-Organization-ID")); org != "" && !strings.EqualFold(org, "all") {
		q.Set("organization_id", org)
	}
	target := oamProjectsTarget(base, q)
	raw, status, err := proxyPeerGET(ctx, target, r)
	if err != nil {
		return nil, err
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("oam returned %d", status)
	}
	var payload struct {
		Projects []oamDirectoryProject `json:"projects"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, err
	}
	for i := range payload.Projects {
		row := &payload.Projects[i]
		if row.directoryID() == projectID {
			return row, nil
		}
	}
	return nil, nil
}

// resolveSCMFromOAMProject fills connector_id / repo_full_name from the OAM
// directory row when the client omitted them. Fail closed when the concrete
// project has no connector_ids or external_key.
func resolveSCMFromOAMProject(r *http.Request, connectorID, repoFullName string) (string, string, string, int) {
	connectorID = strings.TrimSpace(connectorID)
	repoFullName = strings.TrimSpace(repoFullName)
	if connectorID != "" && repoFullName != "" {
		return connectorID, repoFullName, "", 0
	}
	base := peerOAMURL()
	if base == "" {
		return connectorID, repoFullName, "", 0
	}
	proj := strings.TrimSpace(r.Header.Get("X-Project-ID"))
	if proj == "" || strings.EqualFold(proj, "all") {
		return connectorID, repoFullName, "", 0
	}
	row, err := lookupOAMDirectoryProject(r.Context(), r, base, "osa", proj)
	if err != nil {
		return "", "", "could not resolve project connectors from OAM: " + err.Error(), 503
	}
	if row == nil {
		return "", "", fmt.Sprintf("project %q is disabled for product osa (OAM disabled_products)", proj), 403
	}
	if connectorID == "" {
		if len(row.ConnectorIDs) == 0 || strings.TrimSpace(row.ConnectorIDs[0]) == "" {
			return "", "", "project has no connector_ids; attach a connector in Account Manager", 400
		}
		connectorID = strings.TrimSpace(row.ConnectorIDs[0])
	}
	if repoFullName == "" {
		repoFullName = strings.TrimSpace(row.ExternalKey)
		if repoFullName == "" || !strings.Contains(repoFullName, "/") {
			return "", "", "project has no external_key (owner/repo); import a GitHub project in Account Manager", 400
		}
	}
	return connectorID, repoFullName, "", 0
}
