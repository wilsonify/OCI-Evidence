package model

import "time"

type State string

const (
	StatePass          State = "PASS"
	StateFail          State = "FAIL"
	StateWarn          State = "WARN"
	StateNotApplicable State = "NOT_APPLICABLE"
	StateUnsupported   State = "UNSUPPORTED"
	StateError         State = "ERROR"
	StateStale         State = "STALE"
	StateRevoked       State = "REVOKED"
	StateUnknown       State = "UNKNOWN"
)

type Descriptor struct {
	Digest    string            `json:"digest"`
	MediaType string            `json:"mediaType,omitempty"`
	Size        int64             `json:"size,omitempty"`
	ArtifactType string           `json:"artifactType,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

type Artifact struct {
	Reference         string            `json:"reference"`
	Repository        string            `json:"repository"`
	Digest            string            `json:"digest"`
	ManifestMediaType string            `json:"manifestMediaType,omitempty"`
	ArtifactType      string            `json:"artifactType,omitempty"`
	Config            Descriptor        `json:"config,omitempty"`
	Layers            []Descriptor      `json:"layers,omitempty"`
	MediaTypes        []string          `json:"mediaTypes,omitempty"`
	Annotations       map[string]string `json:"annotations,omitempty"`
}

type WorkerIdentity struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Digest  string `json:"digest"`
}

type DatabaseIdentity struct {
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
	Digest  string `json:"digest,omitempty"`
}

type Evidence struct {
	SchemaVersion       string           `json:"schemaVersion"`
	ScanKey             string           `json:"scanKey"`
	Capability          string           `json:"capability"`
	Subject             Artifact         `json:"subject"`
	Worker              WorkerIdentity   `json:"worker"`
	Database            DatabaseIdentity `json:"database,omitempty"`
	ConfigurationDigest string           `json:"configurationDigest"`
	State               State            `json:"state"`
	Result              any              `json:"result,omitempty"`
	ProducedAt          time.Time        `json:"producedAt"`
	Revoked             bool             `json:"revoked,omitempty"`
	Stale               bool             `json:"stale,omitempty"`
}

type Decision struct {
	State    State               `json:"state"`
	Reasons  []string            `json:"reasons"`
	Controls map[string]State    `json:"controls"`
	Evidence map[string]Evidence `json:"evidence"`
}

type VerifyResult struct {
	Artifact  Artifact   `json:"artifact"`
	Evidence  []Evidence `json:"evidence"`
	Decision  Decision   `json:"decision"`
	ReusedAny bool       `json:"reusedAny"`
}
