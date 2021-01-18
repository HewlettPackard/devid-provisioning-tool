package logger

type dummy struct{}

func (dummy) Debug(args ...interface{})   {}
func (dummy) Print(args ...interface{})   {}
func (dummy) Info(args ...interface{})    {}
func (dummy) Warn(args ...interface{})    {}
func (dummy) Warning(args ...interface{}) {}
func (dummy) Error(args ...interface{})   {}
func (dummy) Fatal(args ...interface{})   {}

func (dummy) Debugf(format string, args ...interface{})   {}
func (dummy) Infof(format string, args ...interface{})    {}
func (dummy) Printf(format string, args ...interface{})   {}
func (dummy) Warnf(format string, args ...interface{})    {}
func (dummy) Warningf(format string, args ...interface{}) {}
func (dummy) Errorf(format string, args ...interface{})   {}
func (dummy) Fatalf(format string, args ...interface{})   {}

func (dummy) WithField(key string, value interface{}) Logger {
	return dummy{}
}
