package methods

import "strings"

type Registry struct {
	methods []Method
}

func NewRegistry() *Registry {
	return &Registry{}
}

func (r *Registry) Register(m Method) {
	r.methods = append(r.methods, m)
}

func (r *Registry) All() []Method {
	return r.methods
}

func (r *Registry) ByProtocol(name string) []Method {
	name = strings.ToUpper(name)
	var out []Method
	for _, m := range r.methods {
		if strings.ToUpper(m.Protocol) == name {
			out = append(out, m)
		}
	}
	return out
}

func (r *Registry) ByFunction(name string) []Method {
	name = strings.ToLower(name)
	var out []Method
	for _, m := range r.methods {
		if strings.ToLower(m.Function) == name {
			out = append(out, m)
		}
	}
	return out
}

func (r *Registry) Protocols() []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range r.methods {
		if !seen[m.Protocol] {
			seen[m.Protocol] = true
			out = append(out, m.Protocol)
		}
	}
	return out
}

func (r *Registry) Count() int {
	return len(r.methods)
}

func DefaultRegistry() *Registry {
	r := NewRegistry()
	registerEFSR(r)
	registerRPRN(r)
	registerPAR(r)
	registerDFSNM(r)
	registerFSRVP(r)
	registerEVEN(r)
	return r
}
