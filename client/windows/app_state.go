package main

import "time"

func maskKey(k string) string {
	if len(k) <= 12 {
		return "****"
	}
	return k[:12] + "********"
}

func (a *App) GetState() State {
	logEpoch := a.currentLogEpoch()

	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.getStateLocked(logEpoch)
}

func (a *App) getStateLocked(logEpoch uint64) State {
	cfg := a.cfg
	if cfg == nil {
		cfg = &Config{}
	}

	var lastSync *time.Time
	if !a.lastSyncAt.IsZero() {
		t := a.lastSyncAt
		lastSync = &t
	}

	tunnels := make([]TunnelVO, len(a.tunnels))
	copy(tunnels, a.tunnels)
	running := a.mgr.RunningSet()
	for i := range tunnels {
		_, isRunning := running[tunnels[i].ID]
		tunnels[i].Running = isRunning
		tunnels[i].Registered = a.registered[tunnels[i].ID]
		if tunnels[i].Running && !tunnels[i].Registered {
			if at, ok := a.connectAt[tunnels[i].ID]; ok {
				tunnels[i].PendingSeconds = int(time.Since(at).Seconds())
			}
		}
		if e, ok := a.tunnelErrs[tunnels[i].ID]; ok {
			at := e.at
			tunnels[i].LastError = e.msg
			tunnels[i].LastErrorAt = &at
		}
	}
	if tunnels == nil {
		tunnels = []TunnelVO{}
	}

	state := State{
		ServerURL:      cfg.ServerURL,
		ServerFixed:    serverFixed(),
		NeedsServerURL: !serverFixed() && cfg.ServerURL == "",
		LoggedIn:       cfg.APIKey != "",
		Username:       a.username,
		APIKeyMask:     a.apiKeyMask,
		GatewayHost:    a.gatewayHost,
		GatewayPort:    a.gatewayPort,
		TunnelDomain:   a.tunnelDomain,
		Tunnels:        tunnels,
		TrafficUsed:    a.trafficUsed,
		TrafficQuota:   a.trafficQuota,
		Exceeded:       a.exceeded,
		Group:          a.group,
		PaymentEnabled: a.paymentEnabled,
		BalanceCents:   a.balanceCents,
		SyncErr:        firstNonEmpty(a.syncErr, a.cleanupErr),
		LastSyncAt:     lastSync,
		ConfigError:    a.cfgErr,
		Version:        Version(),
		LogEpoch:       logEpoch,
		StateSeq:       a.stateSeq,
		AuthGen:        a.authGeneration,
		Running:        len(running) > 0,
		FrpcFound:      a.mgr.Available(),
		FrpcPath:       a.mgr.ExePath(),
	}
	if fixed := defaultServerURL(); fixed != "" {
		state.ServerURL = fixed
	}
	if p, err := frpcTunnelsDir(); err == nil {
		state.ConfigPath = p
	}
	return state
}
