package network

type NetworkIsolator interface {
	IsolateHost() error
	RestoreHost() error
}

func NewNetworkIsolator() NetworkIsolator {
	return newNetworkIsolator()
}
