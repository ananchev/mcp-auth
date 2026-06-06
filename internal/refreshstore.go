package internal

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"sync"
	"time"
)

// Refresh-token errors surfaced to the token endpoint as invalid_grant.
var (
	errRefreshNotFound = errors.New("refresh token not found")
	errRefreshExpired  = errors.New("refresh token expired")
	errRefreshReuse    = errors.New("refresh token reuse detected")
)

// refreshRecord is the persisted state for one refresh token. Tokens are stored
// keyed by SHA-256 hash (never plaintext). A token rotated out is kept (Used=true)
// only so a later replay can be detected and the whole family revoked.
type refreshRecord struct {
	Subject  string    `json:"subject"`
	Expiry   time.Time `json:"expiry"`
	FamilyID string    `json:"family_id"`
	Used     bool      `json:"used"`
}

// refreshStore is a file-backed, mutex-guarded refresh-token store with
// rotation + reuse detection. Persistence lets refresh tokens survive AS
// restarts/redeploys so clients are not forced through full re-auth.
type refreshStore struct {
	mu      sync.Mutex
	path    string
	ttl     time.Duration
	records map[string]*refreshRecord // key: sha256hex(token)
}

func newRefreshStore(path string, ttl time.Duration) (*refreshStore, error) {
	s := &refreshStore{path: path, ttl: ttl, records: map[string]*refreshRecord{}}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func hashToken(tok string) string {
	h := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(h[:])
}

func (s *refreshStore) load() error {
	b, err := os.ReadFile(s.path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if len(b) == 0 {
		return nil
	}
	if err := json.Unmarshal(b, &s.records); err != nil {
		return err
	}
	// Drop anything already expired so the file doesn't grow without bound.
	now := time.Now()
	for k, r := range s.records {
		if now.After(r.Expiry) {
			delete(s.records, k)
		}
	}
	return nil
}

func (s *refreshStore) persistLocked() error {
	b, err := json.MarshalIndent(s.records, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path) // atomic replace
}

// issue mints a new refresh token. Pass familyID="" to start a new family
// (initial auth-code grant); pass an existing family on rotation.
func (s *refreshStore) issue(subject, familyID string) (string, error) {
	tok, err := randomToken(32)
	if err != nil {
		return "", err
	}
	if familyID == "" {
		if familyID, err = randomToken(16); err != nil {
			return "", err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records[hashToken(tok)] = &refreshRecord{
		Subject:  subject,
		Expiry:   time.Now().Add(s.ttl),
		FamilyID: familyID,
	}
	if err := s.persistLocked(); err != nil {
		return "", err
	}
	return tok, nil
}

// redeem validates a refresh token and rotates it: the presented token is marked
// used and a fresh token is issued in the same family. Replaying an already-used
// token revokes the entire family (RFC 9700 rotation/replay defence).
func (s *refreshStore) redeem(tok string) (subject, newTok string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := hashToken(tok)
	rec, ok := s.records[key]
	if !ok {
		return "", "", errRefreshNotFound
	}
	if rec.Used {
		s.revokeFamilyLocked(rec.FamilyID)
		_ = s.persistLocked()
		return "", "", errRefreshReuse
	}
	if time.Now().After(rec.Expiry) {
		delete(s.records, key)
		_ = s.persistLocked()
		return "", "", errRefreshExpired
	}

	rec.Used = true
	newTok, err = randomToken(32)
	if err != nil {
		return "", "", err
	}
	s.records[hashToken(newTok)] = &refreshRecord{
		Subject:  rec.Subject,
		Expiry:   time.Now().Add(s.ttl),
		FamilyID: rec.FamilyID,
	}
	if err := s.persistLocked(); err != nil {
		return "", "", err
	}
	return rec.Subject, newTok, nil
}

func (s *refreshStore) revokeFamilyLocked(familyID string) {
	for k, r := range s.records {
		if r.FamilyID == familyID {
			delete(s.records, k)
		}
	}
}
