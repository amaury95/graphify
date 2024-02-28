package graphify

type Common struct {
	Observer   IObserver[Topic]
	Connection IConnection
}
