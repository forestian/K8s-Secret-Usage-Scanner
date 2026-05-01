package manifest

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// ParseFile reads a single YAML, multi-document YAML, or JSON file and
// returns the decoded resources. Returns a non-nil error only for I/O
// problems; YAML parse errors are returned as ParseError entries.
func ParseFile(path string) ([]*KubeResource, []ParseError) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, []ParseError{{File: path, Err: err}}
	}

	ext := strings.ToLower(filepath.Ext(path))
	if ext == ".json" {
		return parseJSON(path, data)
	}
	return parseYAML(path, data)
}

// ParseError carries a file-level or document-level error.
type ParseError struct {
	File string
	Doc  int
	Err  error
}

func (e ParseError) Error() string {
	if e.Doc > 0 {
		return fmt.Sprintf("%s (doc %d): %v", e.File, e.Doc, e.Err)
	}
	return fmt.Sprintf("%s: %v", e.File, e.Err)
}

func parseYAML(path string, data []byte) ([]*KubeResource, []ParseError) {
	var resources []*KubeResource
	var errs []ParseError

	decoder := yaml.NewDecoder(strings.NewReader(string(data)))
	docIndex := 0
	for {
		docIndex++
		var raw map[string]interface{}
		err := decoder.Decode(&raw)
		if err == io.EOF {
			break
		}
		if err != nil {
			errs = append(errs, ParseError{File: path, Doc: docIndex, Err: err})
			continue
		}
		if raw == nil {
			continue
		}
		res := buildResource(raw, path)
		if res == nil {
			continue
		}
		resources = append(resources, res)
	}
	return resources, errs
}

func parseJSON(path string, data []byte) ([]*KubeResource, []ParseError) {
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, []ParseError{{File: path, Err: err}}
	}
	res := buildResource(raw, path)
	if res == nil {
		return nil, nil
	}
	return []*KubeResource{res}, nil
}

func buildResource(raw map[string]interface{}, path string) *KubeResource {
	kind, _ := raw["kind"].(string)
	apiVersion, _ := raw["apiVersion"].(string)
	if kind == "" {
		return nil
	}

	res := &KubeResource{
		APIVersion: apiVersion,
		Kind:       kind,
		Raw:        raw,
		SourceFile: path,
	}

	if meta, ok := raw["metadata"].(map[string]interface{}); ok {
		res.Metadata.Name, _ = meta["name"].(string)
		res.Metadata.Namespace, _ = meta["namespace"].(string)
		if ann, ok := meta["annotations"].(map[string]interface{}); ok {
			res.Metadata.Annotations = make(map[string]string)
			for k, v := range ann {
				if sv, ok := v.(string); ok {
					res.Metadata.Annotations[k] = sv
				}
			}
		}
	}
	return res
}

// WalkDir recursively collects all .yaml/.yml/.json files under root.
func WalkDir(root string) ([]string, error) {
	var files []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".yaml" || ext == ".yml" || ext == ".json" {
			files = append(files, path)
		}
		return nil
	})
	return files, err
}
