package report

import (
	"encoding/json"
	"io"

	"github.com/k8s-secret-usage-scanner/ksecret-map/internal/model"
)

// WriteJSON renders the report as pretty-printed JSON.
func WriteJSON(r *model.ScanReport, w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}
