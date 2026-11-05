package state

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var t0 = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)

func sample() *State {
	st := New(t0)
	st.MarkSeen("a", t0.Add(-2*time.Hour))
	st.MarkSeen("b", t0.Add(-time.Minute))
	return st
}

func TestStateOperations(t *testing.T) {
	st := sample()
	assert.True(t, st.IsSeen("a"))
	assert.False(t, st.IsSeen("z"))

	clone := st.Clone()
	st.Prune(t0.Add(-time.Hour))
	assert.False(t, st.IsSeen("a"), "older than the window")
	assert.True(t, st.IsSeen("b"))
	assert.True(t, clone.IsSeen("a"), "the clone is independent")

	data, err := st.Marshal()
	require.NoError(t, err)
	back, err := Unmarshal(data)
	require.NoError(t, err)
	assert.True(t, back.Cursor.Equal(t0))
	assert.True(t, back.IsSeen("b"))

	empty, err := Unmarshal([]byte(`{"cursor":"2026-11-05T12:00:00Z"}`))
	require.NoError(t, err)
	assert.NotNil(t, empty.Seen)
	_, err = Unmarshal([]byte("{"))
	assert.Error(t, err)
}

func TestMemoryStore(t *testing.T) {
	m := &Memory{}
	_, found, err := m.Load(context.Background())
	require.NoError(t, err)
	assert.False(t, found)
	require.NoError(t, m.Save(context.Background(), sample()))
	st, found, err := m.Load(context.Background())
	require.NoError(t, err)
	assert.True(t, found)
	assert.True(t, st.IsSeen("a"))
	assert.Equal(t, "memory", m.Name())
}

func TestFileStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "state.json")
	f := &File{Path: path}
	_, found, err := f.Load(context.Background())
	require.NoError(t, err)
	assert.False(t, found)

	require.NoError(t, f.Save(context.Background(), sample()))
	st, found, err := f.Load(context.Background())
	require.NoError(t, err)
	assert.True(t, found)
	assert.True(t, st.Cursor.Equal(t0))
	assert.Contains(t, f.Name(), path)

	require.NoError(t, os.WriteFile(path, []byte("garbage"), 0o600))
	_, _, err = f.Load(context.Background())
	assert.Error(t, err)

	entries, err := os.ReadDir(filepath.Dir(path))
	require.NoError(t, err)
	assert.Len(t, entries, 1, "no temporary file left behind")
}

// fakeAPI is a minimal ConfigMap API server
type fakeAPI struct {
	mu       sync.Mutex
	cm       *configMap
	requests []string
	failWith int
}

func (f *fakeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, r.Method+" "+r.URL.Path)
	if r.Header.Get("Authorization") != "Bearer test-token" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if f.failWith != 0 {
		w.WriteHeader(f.failWith)
		_, _ = io.WriteString(w, `{"message":"forbidden"}`)
		return
	}
	const item = "/api/v1/namespaces/vault/configmaps/vw-state"
	switch {
	case r.Method == http.MethodGet && r.URL.Path == item:
		if f.cm == nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(f.cm)
	case r.Method == http.MethodPatch && r.URL.Path == item:
		if f.cm == nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Header.Get("Content-Type") != "application/merge-patch+json" {
			w.WriteHeader(http.StatusUnsupportedMediaType)
			return
		}
		var patch configMap
		_ = json.NewDecoder(r.Body).Decode(&patch)
		for k, v := range patch.Data {
			f.cm.Data[k] = v
		}
		_ = json.NewEncoder(w).Encode(f.cm)
	case r.Method == http.MethodPost && r.URL.Path == "/api/v1/namespaces/vault/configmaps":
		var cm configMap
		_ = json.NewDecoder(r.Body).Decode(&cm)
		f.cm = &cm
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(cm)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func newFakeStore(t *testing.T) (*Kubernetes, *fakeAPI) {
	t.Helper()
	api := &fakeAPI{}
	srv := httptest.NewServer(api)
	t.Cleanup(srv.Close)
	token := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(token, []byte("test-token\n"), 0o600))
	return newKubernetesWith(srv.URL, token, "vw-state", "vault", map[string]string{"app": "vw"}, srv.Client()), api
}

func TestKubernetesStoreCreatePatchLoad(t *testing.T) {
	k, api := newFakeStore(t)
	ctx := context.Background()

	_, found, err := k.Load(ctx)
	require.NoError(t, err)
	assert.False(t, found, "missing configmap")

	require.NoError(t, k.Save(ctx, sample()), "creates the configmap")
	assert.Equal(t, "vw", api.cm.Metadata.Labels["app"])

	st := sample()
	st.MarkSeen("c", t0)
	require.NoError(t, k.Save(ctx, st), "patches it")

	loaded, found, err := k.Load(ctx)
	require.NoError(t, err)
	assert.True(t, found)
	assert.True(t, loaded.IsSeen("c"))
	assert.Equal(t, []string{
		"GET /api/v1/namespaces/vault/configmaps/vw-state",
		"PATCH /api/v1/namespaces/vault/configmaps/vw-state",
		"POST /api/v1/namespaces/vault/configmaps",
		"PATCH /api/v1/namespaces/vault/configmaps/vw-state",
		"GET /api/v1/namespaces/vault/configmaps/vw-state",
	}, api.requests)
	assert.Equal(t, "kubernetes:configmap/vault/vw-state", k.Name())
}

func TestKubernetesStoreErrors(t *testing.T) {
	k, api := newFakeStore(t)
	ctx := context.Background()

	api.cm = &configMap{Data: map[string]string{}}
	_, found, err := k.Load(ctx)
	require.NoError(t, err)
	assert.False(t, found, "empty state key")

	api.cm.Data[stateKey] = "not json"
	_, _, err = k.Load(ctx)
	assert.Error(t, err)

	api.failWith = http.StatusForbidden
	_, _, err = k.Load(ctx)
	assert.ErrorContains(t, err, "HTTP 403")
	assert.ErrorContains(t, k.Save(ctx, sample()), "HTTP 403")

	k.tokenPath = filepath.Join(t.TempDir(), "missing")
	_, _, err = k.Load(ctx)
	assert.ErrorContains(t, err, "token")
}

func TestNewKubernetesOutsideCluster(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	_, err := NewKubernetes("cm", "ns", nil)
	assert.Error(t, err)

	t.Setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
	t.Setenv("KUBERNETES_SERVICE_PORT", "443")
	_, err = NewKubernetes("cm", "ns", nil)
	assert.Error(t, err, "no service account files outside a pod")
}

func TestTruncate(t *testing.T) {
	long := make([]byte, 400)
	for i := range long {
		long[i] = 'x'
	}
	assert.Len(t, truncate(long), 303)
	assert.Equal(t, "short", truncate([]byte(" short ")))
}
