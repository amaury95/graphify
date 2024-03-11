package graphify

type Common struct {
	Connection IConnection
	Observer   IObserver[Topic]
	Storage    IFileStorage
}
