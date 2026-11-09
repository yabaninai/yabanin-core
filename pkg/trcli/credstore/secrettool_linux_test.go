package credstore

import (
	"os"
	"testing"
)

func TestLinuxStoreFallsBackWithoutSecretTool(t *testing.T) {
	home := t.TempDir()
	store, err := linuxStore(home, &fakeRun{})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := store.(fileStore); !ok {
		t.Fatalf("store %#v", store)
	}
	_ = os.ErrNotExist
}

func TestOpenLinuxSelectsSecretToolWhenInstalled(t *testing.T) {
	store, err := Open(t.TempDir(), &fakeRun{paths: map[string]bool{"secret-tool": true}})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := store.(secretTool); !ok {
		t.Fatalf("store %#v", store)
	}
}

func TestOpenLinuxFallsBackWithoutSecretTool(t *testing.T) {
	store, err := Open(t.TempDir(), &fakeRun{})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := store.(fileStore); !ok {
		t.Fatalf("store %#v", store)
	}
}
