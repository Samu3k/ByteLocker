package protocol

import (
	"errors"
	"strings"
)

var ErrInvalidETag = errors.New("protocol: invalid revision tag")

// Revision tags are concurrency preconditions, not signatures or permissions.
// The HTTP layer must reject multiple If-Match header values before parsing.
type AccountETag struct {
	CredentialGeneration Counter
	RecoveryGeneration   Counter
	EpochID              ID
}

type ObjectETag struct {
	EpochID  ID
	Revision Counter
}

func (tag AccountETag) Valid() bool {
	return tag.CredentialGeneration != 0 && !tag.EpochID.IsZero()
}

func (tag ObjectETag) Valid() bool {
	return tag.Revision != 0 && !tag.EpochID.IsZero()
}

// String includes the quotes required for a strong HTTP ETag. Invalid tags
// produce an empty string and must never be emitted as response headers.
func (tag AccountETag) String() string {
	if !tag.Valid() {
		return ""
	}
	return `"a:` + tag.CredentialGeneration.String() + ":" + tag.RecoveryGeneration.String() + ":" + tag.EpochID.String() + `"`
}

func (tag ObjectETag) String() string {
	if !tag.Valid() {
		return ""
	}
	return `"o:` + tag.EpochID.String() + ":" + tag.Revision.String() + `"`
}

// ParseAccountETag accepts exactly one canonical strong account tag. Lists,
// wildcard, weak validators, whitespace and leading-zero counters fail.
func ParseAccountETag(value string) (AccountETag, error) {
	const maxLength = 2 + 2 + MaxCounterLength + 1 + MaxCounterLength + 1 + EncodedIDLength
	parts, ok := etagParts(value, maxLength, 4)
	if !ok || parts[0] != "a" {
		return AccountETag{}, ErrInvalidETag
	}
	credential, err := ParseCounter(parts[1])
	if err != nil || credential == 0 {
		return AccountETag{}, ErrInvalidETag
	}
	recovery, err := ParseCounter(parts[2])
	if err != nil {
		return AccountETag{}, ErrInvalidETag
	}
	epoch, err := ParseID(parts[3])
	if err != nil {
		return AccountETag{}, ErrInvalidETag
	}
	return AccountETag{CredentialGeneration: credential, RecoveryGeneration: recovery, EpochID: epoch}, nil
}

func ParseObjectETag(value string) (ObjectETag, error) {
	const maxLength = 2 + 2 + EncodedIDLength + 1 + MaxCounterLength
	parts, ok := etagParts(value, maxLength, 3)
	if !ok || parts[0] != "o" {
		return ObjectETag{}, ErrInvalidETag
	}
	epoch, err := ParseID(parts[1])
	if err != nil {
		return ObjectETag{}, ErrInvalidETag
	}
	revision, err := ParseCounter(parts[2])
	if err != nil || revision == 0 {
		return ObjectETag{}, ErrInvalidETag
	}
	return ObjectETag{EpochID: epoch, Revision: revision}, nil
}

func etagParts(value string, maxLength, count int) ([]string, bool) {
	if len(value) < 2 || len(value) > maxLength || value[0] != '"' || value[len(value)-1] != '"' {
		return nil, false
	}
	parts := strings.Split(value[1:len(value)-1], ":")
	return parts, len(parts) == count
}
