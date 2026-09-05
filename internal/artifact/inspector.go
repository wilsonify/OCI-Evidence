package artifact

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/wilsonify/OCI-Evidence/pkg/model"
)

type Inspector interface {
	Inspect(ctx context.Context, reference string) (model.Artifact, error)
}

type DigestOnlyInspector struct{}

func (d DigestOnlyInspector) Inspect(_ context.Context, reference string) (model.Artifact, error) {
	parsed, err := ParseDigestReference(reference)
	if err != nil {
		return model.Artifact{}, err
	}
	return model.Artifact{
		Reference:   reference,
		Repository:  parsed.Repository,
		Digest:      parsed.Digest,
		Annotations: map[string]string{},
	}, nil
}

type RegistryInspector struct{}

func NewRegistryInspector() RegistryInspector { return RegistryInspector{} }

func (r RegistryInspector) Inspect(ctx context.Context, reference string) (model.Artifact, error) {
	parsed, err := ParseDigestReference(reference)
	if err != nil {
		return model.Artifact{}, err
	}
	registryHost, repoPath := splitRepository(parsed.Repository)
	manifestURL := fmt.Sprintf("https://%s/v2/%s/manifests/%s", registryHost, repoPath, parsed.Digest)
	client := &http.Client{}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, manifestURL, nil)
	if err != nil {
		return model.Artifact{}, err
	}
	req.Header.Set("Accept", "application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.index.v1+json, application/vnd.cncf.oras.artifact.manifest.v1+json, application/vnd.docker.distribution.manifest.list.v2+json")
	creds := registryCredentials(parsed.Repository)
	if creds != nil {
		req.SetBasicAuth(creds.username, creds.password)
	}
	resp, err := client.Do(req)
	if err != nil {
		return model.Artifact{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		if token, err := getBearerToken(ctx, client, resp, parsed.Repository); err == nil {
			req.Header.Set("Authorization", "Bearer "+token)
			resp, err = client.Do(req)
			if err != nil {
				return model.Artifact{}, err
			}
			defer resp.Body.Close()
		}
	}
	if resp.StatusCode == http.StatusNotFound {
		return model.Artifact{}, fmt.Errorf("digest not found in registry: %s", parsed.Digest)
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return model.Artifact{}, fmt.Errorf("registry request failed: %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return model.Artifact{}, err
	}
	var manifest struct {
		MediaType    string `json:"mediaType"`
		ArtifactType string `json:"artifactType"`
		Config       struct {
			MediaType string `json:"mediaType"`
			Digest    string `json:"digest"`
			Size      int64  `json:"size"`
		} `json:"config"`
		Layers []struct {
			MediaType string `json:"mediaType"`
			Digest    string `json:"digest"`
			Size      int64  `json:"size"`
		} `json:"layers"`
		Manifests []struct {
			MediaType string `json:"mediaType"`
			Digest    string `json:"digest"`
			Size      int64  `json:"size"`
		} `json:"manifests"`
		Annotations map[string]string `json:"annotations"`
	}
	if err := json.Unmarshal(body, &manifest); err != nil {
		return model.Artifact{}, err
	}
	art := model.Artifact{
		Reference:         reference,
		Repository:        parsed.Repository,
		Digest:            parsed.Digest,
		ManifestMediaType: manifest.MediaType,
		ArtifactType:      manifest.ArtifactType,
		Annotations:       manifest.Annotations,
		Config:            model.Descriptor{Digest: manifest.Config.Digest, MediaType: manifest.Config.MediaType, Size: manifest.Config.Size},
	}
	for _, layer := range manifest.Layers {
		art.Layers = append(art.Layers, model.Descriptor{Digest: layer.Digest, MediaType: layer.MediaType, Size: layer.Size})
	}
	for _, item := range manifest.Manifests {
		art.MediaTypes = append(art.MediaTypes, item.MediaType)
	}
	if art.ManifestMediaType != "" {
		art.MediaTypes = append(art.MediaTypes, art.ManifestMediaType)
	}
	if art.Config.MediaType != "" {
		art.MediaTypes = append(art.MediaTypes, art.Config.MediaType)
	}
	for _, layer := range art.Layers {
		if layer.MediaType != "" {
			art.MediaTypes = append(art.MediaTypes, layer.MediaType)
		}
	}
	if art.Annotations == nil {
		art.Annotations = map[string]string{}
	}
	return art, nil
}

type registryCredential struct {
	username string
	password string
}

func registryCredentials(repo string) *registryCredential {
	if user := os.Getenv("OCI_REGISTRY_USERNAME"); user != "" {
		return &registryCredential{username: user, password: os.Getenv("OCI_REGISTRY_PASSWORD")}
	}
	if user := os.Getenv("REGISTRY_USERNAME"); user != "" {
		return &registryCredential{username: user, password: os.Getenv("REGISTRY_PASSWORD")}
	}
	path := os.Getenv("DOCKER_CONFIG")
	if path == "" {
		path = filepath.Join(os.Getenv("HOME"), ".docker", "config.json")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var cfg struct {
		Auths map[string]struct {
			Auth string `json:"auth"`
		} `json:"auths"`
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil
	}
	host, _ := splitRepository(repo)
	if auth, ok := cfg.Auths[host]; ok {
		if decoded, err := decodeDockerAuth(auth.Auth); err == nil {
			return &registryCredential{username: decoded[0], password: decoded[1]}
		}
	}
	return nil
}

func decodeDockerAuth(value string) ([]string, error) {
	if value == "" {
		return nil, fmt.Errorf("empty auth")
	}
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, err
	}
	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("malformed docker auth")
	}
	return parts, nil
}

func splitRepository(repo string) (string, string) {
	if strings.Contains(repo, "/") {
		parts := strings.SplitN(repo, "/", 2)
		if strings.Contains(parts[0], ".") || strings.Contains(parts[0], ":") || parts[0] == "localhost" {
			return parts[0], parts[1]
		}
	}
	return "registry-1.docker.io", "library/" + repo
}

func getBearerToken(ctx context.Context, client *http.Client, resp *http.Response, repo string) (string, error) {
	wwwAuth := resp.Header.Get("WWW-Authenticate")
	if wwwAuth == "" {
		return "", fmt.Errorf("missing www-authenticate header")
	}
	parts := strings.SplitN(wwwAuth, " ", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return "", fmt.Errorf("unsupported auth scheme: %s", wwwAuth)
	}
	params := map[string]string{}
	for _, item := range strings.Split(parts[1], ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		kv := strings.SplitN(item, "=", 2)
		if len(kv) == 2 {
			params[strings.Trim(kv[0], "\"")] = strings.Trim(kv[1], "\"")
		}
	}
	realm := params["realm"]
	service := params["service"]
	scope := params["scope"]
	if realm == "" || service == "" {
		return "", fmt.Errorf("malformed bearer challenge")
	}
	q := url.Values{}
	q.Set("service", service)
	if scope != "" {
		q.Set("scope", scope)
	}
	if user := os.Getenv("OCI_REGISTRY_USERNAME"); user != "" {
		q.Set("account", user)
	}
	tokenURL := realm + "?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, tokenURL, nil)
	if err != nil {
		return "", err
	}
	if cred := registryCredentials(repo); cred != nil {
		req.SetBasicAuth(cred.username, cred.password)
	}
	res, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	if res.StatusCode < http.StatusOK || res.StatusCode >= http.StatusMultipleChoices {
		return "", fmt.Errorf("token exchange failed: %s", res.Status)
	}
	var tokenResp struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(res.Body).Decode(&tokenResp); err != nil {
		return "", err
	}
	if tokenResp.Token == "" {
		return "", fmt.Errorf("token exchange returned empty token")
	}
	return tokenResp.Token, nil
}
