package toolpolicy

// TOOL-04: starter policy packs. Applying a preset creates concrete policy
// rows the admin then edits — presets are templates, not hidden behavior.
// Patterns are honest best-effort over COMMON tool names (both raw coding
// agents' tools and Yabanin built-ins); they are not exhaustive and the
// doc says so.

// PresetIDs.
const (
	// PresetNetworkOff denies outbound-network-looking tools for every
	// agent of the org (web fetch/browse/http tools, including Yabanin's
	// server-side executor).
	PresetNetworkOff = "network-off"
	// PresetNetworkReadOnly denies tools that look write-shaped on the
	// network (post/publish/send/upload/delete style names).
	PresetNetworkReadOnly = "network-readonly"
	// PresetInternalOnly allows nothing except Yabanin's own server-side
	// executor — the "everything through the controlled egress point"
	// posture.
	PresetInternalOnly = "internal-only"
)

// Preset is a named set of policy templates.
type Preset struct {
	ID          string
	Description string
	Policies    []CreateParams // OrgID/Name are filled by ApplyPreset
}

var presets = map[string]Preset{
	PresetNetworkOff: {
		ID:          PresetNetworkOff,
		Description: "Deny outbound-network tools for every agent (web fetch, browse, http clients — including the server-side yabanin executor).",
		Policies: []CreateParams{
			{Subject: "*", Tool: "web_fetch", Action: ActionDeny, Priority: 50},
			{Subject: "*", Tool: "web_*", Action: ActionDeny, Priority: 60},
			{Subject: "*", Tool: "http_*", Action: ActionDeny, Priority: 60},
			{Subject: "*", Tool: "fetch", Action: ActionDeny, Priority: 60},
			{Subject: "*", Tool: "fetch_*", Action: ActionDeny, Priority: 60},
			{Subject: "*", Tool: "browse", Action: ActionDeny, Priority: 60},
			{Subject: "*", Tool: "browse_*", Action: ActionDeny, Priority: 60},
			{Subject: "*", Tool: "url_*", Action: ActionDeny, Priority: 70},
			{Subject: "*", Tool: "curl", Action: ActionDeny, Priority: 70},
			{Subject: "*", Tool: "yabanin:web_fetch", Action: ActionDeny, Priority: 40},
			{Subject: "*", Tool: "yabanin:http_*", Action: ActionDeny, Priority: 40},
			{Subject: "*", Tool: "yabanin:dns_lookup", Action: ActionDeny, Priority: 40},
		},
	},
	PresetNetworkReadOnly: {
		ID:          PresetNetworkReadOnly,
		Description: "Allow read-shaped network tools, deny write-shaped ones (post/publish/send/upload/delete-style tool names).",
		// Trailing-star patterns only (engine constraint): write-shaped
		// verbs as exact common names + verb_* suffix families.
		Policies: []CreateParams{
			{Subject: "*", Tool: "http_post", Action: ActionDeny, Priority: 50},
			{Subject: "*", Tool: "http_put", Action: ActionDeny, Priority: 50},
			{Subject: "*", Tool: "http_delete", Action: ActionDeny, Priority: 50},
			{Subject: "*", Tool: "http_patch", Action: ActionDeny, Priority: 50},
			{Subject: "*", Tool: "post_*", Action: ActionDeny, Priority: 70},
			{Subject: "*", Tool: "publish_*", Action: ActionDeny, Priority: 70},
			{Subject: "*", Tool: "send_*", Action: ActionDeny, Priority: 70},
			{Subject: "*", Tool: "upload_*", Action: ActionDeny, Priority: 70},
			{Subject: "*", Tool: "delete_*", Action: ActionDeny, Priority: 70},
		},
	},
	PresetInternalOnly: {
		ID:          PresetInternalOnly,
		Description: "Deny every tool, then allow only Yabanin's server-side executor — all egress through the controlled point.",
		Policies: []CreateParams{
			{Subject: "*", Tool: "*", Action: ActionDeny, Priority: 500},
			{Subject: "*", Tool: "yabanin:web_fetch", Action: ActionAllow, Priority: 10},
		},
	},
}

// LookupPreset returns the preset by id.
func LookupPreset(id string) (Preset, bool) {
	p, ok := presets[id]
	return p, ok
}

// Presets lists the available starter packs.
func Presets() []Preset {
	out := make([]Preset, 0, len(presets))
	for _, id := range []string{PresetNetworkOff, PresetNetworkReadOnly, PresetInternalOnly} {
		out = append(out, presets[id])
	}
	return out
}
