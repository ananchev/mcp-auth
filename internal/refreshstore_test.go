package internal

import (
	"path/filepath"
	"testing"
	"time"
)

func TestRefreshStore_IssueRedeemRotates(t *testing.T) {
	s, err := newRefreshStore(filepath.Join(t.TempDir(), "r.json"), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := s.issue("user", "")
	if err != nil {
		t.Fatal(err)
	}
	subject, newTok, err := s.redeem(tok)
	if err != nil {
		t.Fatalf("redeem: %v", err)
	}
	if subject != "user" {
		t.Errorf("subject = %q", subject)
	}
	if newTok == "" || newTok == tok {
		t.Error("redeem must return a new, different token")
	}
}

func TestRefreshStore_ReuseRevokesFamily(t *testing.T) {
	s, err := newRefreshStore(filepath.Join(t.TempDir(), "r.json"), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	tok, _ := s.issue("user", "")
	_, newTok, _ := s.redeem(tok)

	if _, _, err := s.redeem(tok); err != errRefreshReuse {
		t.Fatalf("reuse err = %v, want errRefreshReuse", err)
	}
	if _, _, err := s.redeem(newTok); err == nil {
		t.Fatal("family should be revoked: rotated token must no longer redeem")
	}
}

func TestRefreshStore_Expired(t *testing.T) {
	s, err := newRefreshStore(filepath.Join(t.TempDir(), "r.json"), time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	tok, _ := s.issue("user", "")
	time.Sleep(5 * time.Millisecond)
	if _, _, err := s.redeem(tok); err != errRefreshExpired {
		t.Fatalf("err = %v, want errRefreshExpired", err)
	}
}

func TestRefreshStore_PersistsAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "r.json")
	s1, err := newRefreshStore(path, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	tok, _ := s1.issue("user", "")

	// Reopen from the same file — token must still redeem.
	s2, err := newRefreshStore(path, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s2.redeem(tok); err != nil {
		t.Fatalf("token did not survive reopen: %v", err)
	}
}

func TestRefreshStore_NotFound(t *testing.T) {
	s, _ := newRefreshStore(filepath.Join(t.TempDir(), "r.json"), time.Hour)
	if _, _, err := s.redeem("nope"); err != errRefreshNotFound {
		t.Fatalf("err = %v, want errRefreshNotFound", err)
	}
}
