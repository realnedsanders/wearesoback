package model

import (
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
)

// Attr is a structural fact a kind records about its target.
type Attr struct {
	Name string // SysML attribute name
	Key  string // dotted YAML key it is read from; empty when the scanner sets it
	Type string // String, Integer or Boolean
}

// Kind is a family of anchor targets and the library definition its elements are typed by.
type Kind struct {
	Def   string // definition in package WASB
	Usage string // "part" or "action"
	Attrs []Attr
	// Complete kinds' attributes say everything their hash does, so lastHash is optional.
	Complete bool
}

// Kinds are the anchor kinds wasb scans for.
var Kinds = map[string]Kind{
	"go.func": {Def: "GoFunc", Usage: "action", Attrs: []Attr{{"signature", "", "String"}}, Complete: true},
	"zarf.component": {Def: "ZarfComponent", Usage: "part", Attrs: []Attr{
		{"required", "required", "Boolean"}, {"flavor", "only.flavor", "String"}}},
	"helm.template": {Def: "HelmTemplate", Usage: "part"},
	"uds.allow": {Def: "UDSAllow", Usage: "part", Attrs: []Attr{
		{"direction", "direction", "String"}, {"remoteGenerated", "remoteGenerated", "String"},
		{"remoteNamespace", "remoteNamespace", "String"}, {"portNumber", "port", "Integer"},
		{"description", "description", "String"}}},
	"uds.expose": {Def: "UDSExpose", Usage: "part", Attrs: []Attr{
		{"service", "service", "String"}, {"host", "host", "String"}, {"gateway", "gateway", "String"},
		{"portNumber", "port", "Integer"}, {"description", "description", "String"}}},
	"uds.sso": {Def: "UDSSso", Usage: "part", Attrs: []Attr{
		{"clientId", "clientId", "String"}, {"protocol", "protocol", "String"}}},
	"uds.monitor": {Def: "UDSMonitor", Usage: "part", Attrs: []Attr{
		{"portName", "portName", "String"}, {"monitorKind", "kind", "String"}, {"description", "description", "String"}}},
	"uds.task": {Def: "UDSTask", Usage: "part", Attrs: []Attr{{"description", "description", "String"}}},
	"gha.job":  {Def: "GHAJob", Usage: "part", Attrs: []Attr{{"runsOn", "runs-on", "String"}}},
}

// kindDefs writes the library definitions of every kind.
func kindDefs() string {
	var b strings.Builder
	for _, name := range slices.Sorted(maps.Keys(Kinds)) {
		k := Kinds[name]
		fmt.Fprintf(&b, "    /* Elements anchored with kind %q. */\n    %s def %s {\n", name, k.Usage, k.Def)
		for _, a := range k.Attrs {
			fmt.Fprintf(&b, "        attribute %s : %s;\n", a.Name, a.Type)
		}
		b.WriteString("    }\n\n")
	}
	return b.String()
}

// Literal writes a Go string, integer or bool as a SysML literal.
func Literal(v any) string {
	switch v := v.(type) {
	case string:
		return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(v) + `"`
	case int:
		return strconv.Itoa(v)
	case int64:
		return strconv.FormatInt(v, 10)
	case bool:
		return strconv.FormatBool(v)
	}
	return ""
}

// Name writes s as a quoted SysML name.
func Name(s string) string {
	return "'" + strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(s) + "'"
}
