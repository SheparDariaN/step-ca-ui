package handlers

import (
	"encoding/json"
	"net/http"
	"os/exec"
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
	data := h.base(w, r, "prov")
	data["Provisioners"] = provs
	data["CAURL"] = ca.URL
	data["RootCert"] = ca.RootCert
	data["Provisioner"] = ca.Provisioner
	data["CAConfigured"] = ca.Configured
	h.render(w, "provisioners", data)
}
