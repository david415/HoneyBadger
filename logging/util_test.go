package logging

type TestSignalWriter struct {
	lastWrite  []byte
	signalChan chan bool
	closeChan  chan bool
}

func NewTestSignalWriter() *TestSignalWriter {
	return &TestSignalWriter{
		signalChan: make(chan bool),
		closeChan:  make(chan bool),
	}
}

func (w *TestSignalWriter) Write(data []byte) (int, error) {
	w.lastWrite = data
	w.signalChan <- true
	return len(data), nil
}

func (w *TestSignalWriter) Close() error {
	w.closeChan <- true
	return nil
}
