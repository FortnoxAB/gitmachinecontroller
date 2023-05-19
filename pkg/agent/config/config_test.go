package config

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFindMasterForConnection(t *testing.T) {
	config := &Config{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := json.NewEncoder(w).Encode(config)
		assert.NoError(t, err)
		fmt.Fprintln(w, "Hello, client")
	}))
	config.Masters = []*Master{
		{
			URL:  ts.URL + "?z1-1",
			Zone: "z1",
		},
		{
			URL:  ts.URL + "?z1-2",
			Zone: "z1",
		},
		{
			URL:  ts.URL + "?z2-2",
			Zone: "z2",
		},
		{
			URL:  ts.URL + "?z2-1",
			Zone: "z2",
		},
		{
			URL:  ts.URL + "?z3-1",
			Zone: "z3",
		},
	}

	defer ts.Close()

	s := config.FindMasterForConnection(context.Background(), "/tmp/gmc.json", "z3")
	assert.Contains(t, s, "z3-1")

	s = config.FindMasterForConnection(context.Background(), "/tmp/gmc.json", "z2")
	assert.Contains(t, s, "z2-1")
	fmt.Println(s)

}
