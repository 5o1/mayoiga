package app

import (
	"encoding/json"
	"fmt"
)

func renderXray(p profile) ([]byte, error) {
	cfg := map[string]any{
		"log":       map[string]any{"loglevel": "warning"},
		"inbounds":  []any{},
		"outbounds": []any{},
		"routing":   map[string]any{"domainStrategy": "AsIs", "rules": []any{}},
	}
	inbounds := cfg["inbounds"].([]any)
	outbounds := cfg["outbounds"].([]any)
	rules := cfg["routing"].(map[string]any)["rules"].([]any)
	for i, m := range p.Mappings {
		lh, lp, err := splitAddress(m.Listen)
		if err != nil {
			return nil, fmt.Errorf("%s listen: %w", m.Name, err)
		}
		inTag := "in-" + m.Name
		outTag := "out-" + m.Name
		if m.Kind == "pull" {
			if m.TargetNode != "" {
				return nil, fmt.Errorf("%s is an automatic pull; runtime routing cannot be represented as one static Xray document", m.Name)
			}
			inbounds = append(inbounds, map[string]any{"tag": inTag, "listen": lh, "port": lp, "protocol": "dokodemo-door", "settings": map[string]any{"address": "127.0.0.1", "port": 1, "network": "tcp"}})
			out, err := vlessOutbound(outTag, m)
			if err != nil {
				return nil, err
			}
			outbounds = append(outbounds, out)
		} else {
			inbounds = append(inbounds, vlessInbound(inTag, lh, lp, m))
			if m.Kind == "publish" {
				outbounds = append(outbounds, map[string]any{"tag": outTag, "protocol": "freedom", "settings": map[string]any{"redirect": m.Target}})
			} else {
				out, err := vlessOutbound(outTag, m)
				if err != nil {
					return nil, err
				}
				outbounds = append(outbounds, out)
			}
		}
		rules = append(rules, map[string]any{"type": "field", "inboundTag": []string{inTag}, "outboundTag": outTag})
		_ = i
	}
	cfg["inbounds"] = inbounds
	cfg["outbounds"] = outbounds
	cfg["routing"].(map[string]any)["rules"] = rules
	return json.MarshalIndent(cfg, "", "  ")
}

func vlessInbound(tag, host string, port int, m mapping) map[string]any {
	return map[string]any{"tag": tag, "listen": host, "port": port, "protocol": "vless",
		"settings": map[string]any{"clients": []any{map[string]any{"id": m.UUID}}, "decryption": "none"},
		"streamSettings": map[string]any{"network": "tcp", "security": "tls",
			"tlsSettings": map[string]any{"minVersion": "1.3", "certificates": []any{map[string]any{
				"certificateFile": m.Certificate, "keyFile": m.Key, "oneTimeLoading": true,
			}}}}}
}

func vlessOutbound(tag string, m mapping) (map[string]any, error) {
	h, p, err := splitAddress(m.Upstream)
	if err != nil {
		return nil, fmt.Errorf("%s upstream: %w", m.Name, err)
	}
	upstreamUUID := m.UpstreamUUID
	if upstreamUUID == "" {
		upstreamUUID = m.UUID
	}
	return map[string]any{
		"tag":      tag,
		"protocol": "vless",
		"settings": map[string]any{
			"vnext": []any{map[string]any{
				"address": h,
				"port":    p,
				"users":   []any{map[string]any{"id": upstreamUUID, "encryption": "none"}},
			}},
		},
		"streamSettings": map[string]any{
			"network":     "tcp",
			"security":    "tls",
			"tlsSettings": map[string]any{"serverName": "mayoiga", "pinnedPeerCertSha256": m.PinnedSHA256, "minVersion": "1.3"},
		},
	}, nil
}
