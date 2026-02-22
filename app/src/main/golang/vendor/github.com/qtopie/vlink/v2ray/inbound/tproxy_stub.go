//go:build !linux

package inbound

import "errors"

type TProxyHandler struct {
}

func (h *TProxyHandler) SetConfig(c *InboundConfig) {
}

func (h *TProxyHandler) Start() error {
	return errors.New("tproxy is only supported on linux")
}

func (h *TProxyHandler) Close() error {
	return nil
}
