// (C) Copyright 2021 Hewlett Packard Enterprise Development LP
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.
package logger

import (
	"context"

	"github.com/sirupsen/logrus"
)

type Logger interface {
	Debug(args ...interface{})
	Print(args ...interface{})
	Info(args ...interface{})
	Warn(args ...interface{})
	Warning(args ...interface{})
	Error(args ...interface{})
	Fatal(args ...interface{})

	Debugf(format string, args ...interface{})
	Infof(format string, args ...interface{})
	Printf(format string, args ...interface{})
	Warnf(format string, args ...interface{})
	Warningf(format string, args ...interface{})
	Errorf(format string, args ...interface{})
	Fatalf(format string, args ...interface{})

	WithField(key string, value interface{}) Logger
}

type logrusLogger struct {
	*logrus.Entry
}

func (l logrusLogger) WithField(key string, value interface{}) Logger {
	return logrusLogger{
		Entry: l.Entry.WithField(key, value),
	}
}

var standardLogger Logger = logrusLogger{
	Entry: logrus.NewEntry(logrus.StandardLogger()),
}

func StandardLogger() Logger {
	return standardLogger
}

type contextKey struct{}

var LoggerContextKey = contextKey{}

func ContextWithStandardLogger(parent context.Context) context.Context {
	return ContextWithLogger(parent, standardLogger)
}

func ContextWithLogger(parent context.Context, logger Logger) context.Context {
	return context.WithValue(parent, LoggerContextKey, logger)
}

func ContextWithField(ctx context.Context, key string, value interface{}) context.Context {
	logger := FromContext(ctx)
	if logger != nil {
		return ContextWithLogger(ctx, logger.WithField(key, value))
	}

	return ContextWithLogger(ctx, standardLogger.WithField(key, value))
}

func FromContext(ctx context.Context) Logger {
	value := ctx.Value(LoggerContextKey)
	if value != nil {
		return value.(Logger)
	}

	return nil
}

func Using(ctx context.Context) Logger {
	logger := FromContext(ctx)
	if logger != nil {
		return logger
	}

	return standardLogger
}
