package app

import (
	"encoding/json"
	"testing"
)

func TestRenderXray(t *testing.T) {
	p := profile{Version: 1, Mappings: []mapping{{
		Name: "nas", Kind: "pull", Listen: "127.0.0.1:9000",
		Upstream:     "home.example:18443",
		UUID:         "9c0ca192-7429-4499-a90b-29f0e3b8f73a",
		PinnedSHA256: "b2daf9e07a4977bcffaa4990cc3c8abf260ffa7d512326857423615476bf2164",
	}}}
	b, err := renderXray(p)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatal(err)
	}
}
