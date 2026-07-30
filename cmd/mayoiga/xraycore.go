package main

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/app/proxyman"
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/dokodemo"
	"github.com/xtls/xray-core/proxy/freedom"
	vless "github.com/xtls/xray-core/proxy/vless"
	vlessin "github.com/xtls/xray-core/proxy/vless/inbound"
	vlessout "github.com/xtls/xray-core/proxy/vless/outbound"
	"github.com/xtls/xray-core/transport/internet"
	_ "github.com/xtls/xray-core/transport/internet/tcp"
	xtls "github.com/xtls/xray-core/transport/internet/tls"
	"google.golang.org/protobuf/proto"
)

func startMapping(m mapping) (*core.Instance, error) {
	lh, lp, err := splitAddress(m.Listen)
	if err != nil {
		return nil, err
	}
	receiver := &proxyman.ReceiverConfig{
		PortList: &xnet.PortList{Range: []*xnet.PortRange{xnet.SinglePortRange(xnet.Port(lp))}},
		Listen:   xnet.NewIPOrDomain(xnet.ParseAddress(lh)),
	}
	var inbound proto.Message
	var outbound proto.Message
	var sender *proxyman.SenderConfig

	if m.Kind == "pull" {
		inbound = &dokodemo.Config{Address: xnet.NewIPOrDomain(xnet.LocalHostIP), Port: 1, Networks: []xnet.Network{xnet.Network_TCP}}
		outbound, sender, err = typedVLESSOutbound(m)
	} else {
		receiver.StreamSettings, err = serverStream(m)
		if err == nil {
			inbound = &vlessin.Config{
				Clients:    []*protocol.User{{Account: serial.ToTypedMessage(&vless.Account{Id: m.UUID, Encryption: "none"})}},
				Decryption: "none",
			}
		}
		if m.Kind == "publish" {
			h, p, parseErr := splitAddress(m.Target)
			if parseErr != nil {
				err = parseErr
			} else {
				outbound = &freedom.Config{DestinationOverride: &freedom.DestinationOverride{Server: &protocol.ServerEndpoint{Address: xnet.NewIPOrDomain(xnet.ParseAddress(h)), Port: uint32(p)}}}
			}
		} else {
			outbound, sender, err = typedVLESSOutbound(m)
		}
	}
	if err != nil {
		return nil, err
	}
	cfg := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
		},
		Inbound: []*core.InboundHandlerConfig{{
			Tag: "in-" + m.Name, ReceiverSettings: serial.ToTypedMessage(receiver),
			ProxySettings: serial.ToTypedMessage(inbound),
		}},
		Outbound: []*core.OutboundHandlerConfig{{
			Tag: "out-" + m.Name, SenderSettings: serial.ToTypedMessage(sender),
			ProxySettings: serial.ToTypedMessage(outbound),
		}},
	}
	instance, err := core.New(cfg)
	if err != nil {
		return nil, fmt.Errorf("%s: create embedded Xray: %w", m.Name, err)
	}
	if err := instance.Start(); err != nil {
		instance.Close()
		return nil, fmt.Errorf("%s: start embedded Xray: %w", m.Name, err)
	}
	return instance, nil
}

func typedVLESSOutbound(m mapping) (*vlessout.Config, *proxyman.SenderConfig, error) {
	h, p, err := splitAddress(m.Upstream)
	if err != nil {
		return nil, nil, err
	}
	stream, err := clientStream(m)
	if err != nil {
		return nil, nil, err
	}
	upstreamUUID := m.UpstreamUUID
	if upstreamUUID == "" {
		upstreamUUID = m.UUID
	}
	return &vlessout.Config{Vnext: &protocol.ServerEndpoint{
		Address: xnet.NewIPOrDomain(xnet.ParseAddress(h)), Port: uint32(p),
		User: &protocol.User{Account: serial.ToTypedMessage(&vless.Account{Id: upstreamUUID, Encryption: "none"})},
	}}, &proxyman.SenderConfig{StreamSettings: stream}, nil
}

func serverStream(m mapping) (*internet.StreamConfig, error) {
	cert, err := os.ReadFile(m.Certificate)
	if err != nil {
		return nil, err
	}
	key, err := os.ReadFile(m.Key)
	if err != nil {
		return nil, err
	}
	return streamConfig(&xtls.Config{MinVersion: "1.3", Certificate: []*xtls.Certificate{{
		Certificate: cert,
		Key:         key,
		// Published-service certificates are generated locally and are immutable
		// for the lifetime of an instance. Disable Xray's certificate reload/OCSP
		// ticker so it cannot mutate the certificate slice while TLS handshakes
		// are reading it.
		OneTimeLoading: true,
	}}}), nil
}

func clientStream(m mapping) (*internet.StreamConfig, error) {
	pin, err := hex.DecodeString(m.PinnedSHA256)
	if err != nil || len(pin) != 32 {
		return nil, fmt.Errorf("%s: certificate pin must be 64 hexadecimal characters", m.Name)
	}
	return streamConfig(&xtls.Config{
		ServerName: "mayoiga", MinVersion: "1.3",
		DisableSystemRoot: true, PinnedPeerCertSha256: [][]byte{pin},
	}), nil
}

func streamConfig(tlsConfig *xtls.Config) *internet.StreamConfig {
	return &internet.StreamConfig{
		ProtocolName:     "tcp",
		SecurityType:     serial.GetMessageType(tlsConfig),
		SecuritySettings: []*serial.TypedMessage{serial.ToTypedMessage(tlsConfig)},
	}
}
