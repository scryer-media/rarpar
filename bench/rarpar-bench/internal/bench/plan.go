package bench

import (
	"fmt"
	"path/filepath"
	"sort"
)

func CreatePlan(corpusRoot, seed, lane, family, par2Placement string, warmups, repeats int) (Plan, error) {
	if warmups < 0 || repeats < 1 {
		return Plan{}, fmt.Errorf("warmups must be non-negative and repeats must be positive")
	}
	if lane != "cpu" && lane != "metal" && lane != "docker-cpu" {
		return Plan{}, fmt.Errorf("lane must be cpu, metal, or docker-cpu")
	}
	if family != "" && family != "rar" && family != "par2" {
		return Plan{}, fmt.Errorf("family must be rar or par2")
	}
	if par2Placement != "canonical" && par2Placement != "smart" {
		return Plan{}, fmt.Errorf("PAR2 placement must be canonical or smart")
	}
	var index struct {
		Digest string `json:"digest"`
	}
	if err := readJSON(filepath.Join(corpusRoot, "corpus.json"), &index); err != nil {
		return Plan{}, err
	}
	entries, err := sortedFiles(corpusRoot)
	if err != nil {
		return Plan{}, err
	}
	var ids []string
	for _, path := range entries {
		if filepath.Base(path) != "manifest.json" {
			continue
		}
		var manifest CorpusCaseManifest
		if err := readJSON(path, &manifest); err != nil {
			return Plan{}, err
		}
		if manifest.CorpusDigest != index.Digest {
			return Plan{}, fmt.Errorf("case %q does not match corpus digest", manifest.ID)
		}
		if family != "" && manifest.Config.Family != family {
			continue
		}
		ids = append(ids, manifest.ID)
	}
	sort.Strings(ids)
	if len(ids) == 0 {
		return Plan{}, fmt.Errorf("no corpus cases found")
	}
	order := deterministicOrder(ids, seed)
	cases := make([]PlanCase, len(order))
	for index, id := range order {
		cases[index] = PlanCase{ID: id, Order: index + 1}
	}
	plan := Plan{
		SchemaVersion: PlanSchemaVersion,
		CorpusDigest:  index.Digest,
		Seed:          seed,
		Warmups:       warmups,
		Repeats:       repeats,
		Lane:          lane,
		Par2Placement: par2Placement,
		Cases:         cases,
	}
	encoded, err := canonicalJSON(struct {
		CorpusDigest  string     `json:"corpus_digest"`
		Seed          string     `json:"seed"`
		Warmups       int        `json:"warmups"`
		Repeats       int        `json:"repeats"`
		Lane          string     `json:"lane"`
		Family        string     `json:"family,omitempty"`
		Par2Placement string     `json:"par2_placement"`
		Cases         []PlanCase `json:"cases"`
	}{plan.CorpusDigest, plan.Seed, plan.Warmups, plan.Repeats, plan.Lane, family, plan.Par2Placement, plan.Cases})
	if err != nil {
		return Plan{}, err
	}
	plan.ID = "plan-" + bytesSHA256(encoded)[:16]
	return plan, nil
}

func LoadPlan(path, corpusDigest string) (Plan, error) {
	var plan Plan
	if err := readJSON(path, &plan); err != nil {
		return Plan{}, err
	}
	if plan.SchemaVersion != PlanSchemaVersion || plan.ID == "" || plan.CorpusDigest != corpusDigest || plan.Warmups < 0 || plan.Repeats < 1 || len(plan.Cases) == 0 || (plan.Lane != "cpu" && plan.Lane != "metal" && plan.Lane != "docker-cpu") || (plan.Par2Placement != "canonical" && plan.Par2Placement != "smart") {
		return Plan{}, fmt.Errorf("invalid plan %s", path)
	}
	seen := map[string]bool{}
	for index, item := range plan.Cases {
		if item.ID == "" || item.Order != index+1 || seen[item.ID] {
			return Plan{}, fmt.Errorf("plan has invalid case order")
		}
		seen[item.ID] = true
	}
	return plan, nil
}

func WritePlan(path string, plan Plan) error {
	return writeJSON(path, plan)
}

func deterministicOrder(ids []string, seed string) []string {
	type decorated struct {
		id  string
		key string
	}
	items := make([]decorated, 0, len(ids))
	for _, id := range ids {
		items = append(items, decorated{id: id, key: bytesSHA256([]byte(seed + "\x00" + id))})
	}
	sort.Slice(items, func(left, right int) bool { return items[left].key < items[right].key })
	ordered := make([]string, len(items))
	for index, item := range items {
		ordered[index] = item.id
	}
	return ordered
}
