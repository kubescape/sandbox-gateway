// Package gatewaysock is the node controller's HTTP interface on the unix
// socket node-agent reaches it by.
//
//	POST /v1/sightings   a hostname node-agent saw in a workload's DNS answers
//	GET  /healthz/certs  whether the node can decrypt, and until when
//
// node-agent does not read the second one from this socket: Envoy's health
// listener routes its /healthz/certs path here.
package gatewaysock

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"
)

// Certs is the body of GET /healthz/certs.
type Certs struct {
	// CanDecrypt is false when the node has no intermediate, or the one it
	// holds has less than one leaf lifetime left and no renewal has arrived.
	CanDecrypt bool `json:"canDecrypt"`
	// DecryptValidUntil is the earliest expiry among the leaves held and the
	// intermediate. Absent when there is no intermediate.
	DecryptValidUntil *time.Time `json:"decryptValidUntil,omitempty"`
	// RootFingerprint is the SHA-256, in hex, of the root the node's
	// intermediate chains to.
	RootFingerprint string `json:"rootFingerprint"`
}

// Sighting is the body of POST /v1/sightings.
type Sighting struct {
	// Name is the hostname a workload resolved.
	Name string `json:"name"`
	// Addresses are the addresses in the answer. They are not used here:
	// node-agent keeps the address set.
	Addresses []string `json:"addresses"`
	// BindingIDs are the bindings whose patterns cover the name. They are
	// not used to scope the name: it reaches a pod when one of that pod's
	// own patterns covers it.
	BindingIDs []uint32 `json:"bindingIds"`
}

// maxBody bounds a request body. A sighting is one name and a few addresses.
const maxBody = 64 << 10

// Handler serves the socket's routes.
type Handler struct {
	// Observe records a sighted name and reports whether the host set changed.
	Observe func(name string) (changed bool)
	// Changed is called after a sighting changed the set or left a name
	// waiting, so the listener is rebuilt.
	Changed func()
	// Certs returns the certificate state for GET /healthz/certs.
	Certs func() Certs
	Log   *slog.Logger

	// Sightings counts requests accepted; Learned counts the ones that
	// changed the set.
	Sightings, Learned atomic.Int64
}

// Mux returns the routes.
func (h *Handler) Mux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/sightings", h.sightings)
	mux.HandleFunc("GET /healthz/certs", h.certs)
	return mux
}

// certs always answers 200 when the node controller is up: the body says
// whether the node can decrypt. A node controller that is down is what a
// failed probe of this path means.
func (h *Handler) certs(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("content-type", "application/json")
	var c Certs
	if h.Certs != nil {
		c = h.Certs()
	}
	_ = json.NewEncoder(w).Encode(c)
}

func (h *Handler) sightings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("allow", http.MethodPost)
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
		return
	}
	var s Sighting
	if err := json.Unmarshal(body, &s); err != nil || s.Name == "" {
		http.Error(w, `want {"name": "...", "addresses": [...], "bindingIds": [...]}`, http.StatusBadRequest)
		return
	}
	h.Sightings.Add(1)
	changed := h.Observe(s.Name)
	if changed {
		h.Learned.Add(1)
		if h.Log != nil {
			h.Log.Info("learned a hostname", "name", s.Name, "bindings", len(s.BindingIDs))
		}
	}
	// A name that did not change the set may be waiting for a slot; the
	// rebuild is what starts making room for it.
	if h.Changed != nil {
		h.Changed()
	}
	w.Header().Set("content-type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"changed": changed})
}
