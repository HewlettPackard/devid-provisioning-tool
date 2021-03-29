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
