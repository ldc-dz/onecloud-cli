// Package accounts remembers, per VM host, which personal account the
// onecloud-join step returned, so later connections skip that step.
package accounts

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

// Store is a JSON file mapping host to account.
type Store struct{ Path string }

func (s Store) load() (map[string]string, error) {
	m := map[string]string{}
	data, err := os.ReadFile(s.Path)
	if errors.Is(err, os.ErrNotExist) {
		return m, nil
	}
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return m, nil
	}
	return m, json.Unmarshal(data, &m)
}

// Get returns the cached account for host.
func (s Store) Get(host string) (string, bool) {
	m, err := s.load()
	if err != nil {
		return "", false
	}
	a, ok := m[host]
	return a, ok
}

// Set records the account for host (atomic replace, 0600).
func (s Store) Set(host, account string) error {
	m, err := s.load()
	if err != nil {
		m = map[string]string{}
	}
	m[host] = account
	return s.write(m)
}

// Forget drops the cached account for host.
func (s Store) Forget(host string) error {
	m, err := s.load()
	if err != nil {
		return err
	}
	delete(m, host)
	return s.write(m)
}

func (s Store) write(m map[string]string) error {
	if err := os.MkdirAll(filepath.Dir(s.Path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.Path), ".accounts-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), s.Path)
}
