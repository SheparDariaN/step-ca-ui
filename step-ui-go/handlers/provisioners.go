package handlers

import (
	"encoding/json"
	"net/http"
	"os/exec"

	appdb "step-ui/db"
)

func (h *Handler) Provisioners(w http.ResponseWriter, r *http.Request) {
	ca := h.CA()
	var provs []map[string]interface{}
	if ca.Configured {
		out, err := exec.Command("step", "ca", "provisioner", "list",
			"--ca-url", ca.URL,
			"--root", ca.RootCert,
		).Output()
		if err == nil {
			json.Unmarshal(out, &provs)
		}
	}
	registered, _ := appdb.ListCAProvisioners(h.db)
	registeredSet := map[string]bool{}
	for _, p := range registered {
		registeredSet[p.Name] = true
	}
	type liveProv struct {
		Name       string
		Type       string
		Registered bool
	}
	live := make([]liveProv, 0, len(provs))
	for _, p := range provs {
		name, _ := p["name"].(string)
		typ, _ := p["type"].(string)
		live = append(live, liveProv{Name: name, Type: typ, Registered: registeredSet[name]})
	}
	data := h.base(w, r, "prov")
	data["Provisioners"] = live
	data["RegisteredProvisioners"] = registered
	data["CAURL"] = ca.URL
	data["RootCert"] = ca.RootCert
	data["Provisioner"] = ca.Provisioner
	data["CAConfigured"] = ca.Configured
	h.render(w, "provisioners", data)
}
