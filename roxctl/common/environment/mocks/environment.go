// Code generated by MockGen. DO NOT EDIT.
// Source: environment.go
//
// Generated by this command:
//
//	mockgen -package mocks -destination mocks/environment.go -source environment.go
//

// Package mocks is a generated GoMock package.
package mocks

import (
	io0 "io"
	reflect "reflect"
	time "time"

	common "github.com/stackrox/rox/roxctl/common"
	config "github.com/stackrox/rox/roxctl/common/config"
	io "github.com/stackrox/rox/roxctl/common/io"
	logger "github.com/stackrox/rox/roxctl/common/logger"
	gomock "go.uber.org/mock/gomock"
	grpc "google.golang.org/grpc"
)

// MockEnvironment is a mock of Environment interface.
type MockEnvironment struct {
	ctrl     *gomock.Controller
	recorder *MockEnvironmentMockRecorder
	isgomock struct{}
}

// MockEnvironmentMockRecorder is the mock recorder for MockEnvironment.
type MockEnvironmentMockRecorder struct {
	mock *MockEnvironment
}

// NewMockEnvironment creates a new mock instance.
func NewMockEnvironment(ctrl *gomock.Controller) *MockEnvironment {
	mock := &MockEnvironment{ctrl: ctrl}
	mock.recorder = &MockEnvironmentMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockEnvironment) EXPECT() *MockEnvironmentMockRecorder {
	return m.recorder
}

// ColorWriter mocks base method.
func (m *MockEnvironment) ColorWriter() io0.Writer {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ColorWriter")
	ret0, _ := ret[0].(io0.Writer)
	return ret0
}

// ColorWriter indicates an expected call of ColorWriter.
func (mr *MockEnvironmentMockRecorder) ColorWriter() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ColorWriter", reflect.TypeOf((*MockEnvironment)(nil).ColorWriter))
}

// ConfigStore mocks base method.
func (m *MockEnvironment) ConfigStore() (config.Store, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ConfigStore")
	ret0, _ := ret[0].(config.Store)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ConfigStore indicates an expected call of ConfigStore.
func (mr *MockEnvironmentMockRecorder) ConfigStore() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ConfigStore", reflect.TypeOf((*MockEnvironment)(nil).ConfigStore))
}

// ConnectNames mocks base method.
func (m *MockEnvironment) ConnectNames() (string, string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ConnectNames")
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(string)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// ConnectNames indicates an expected call of ConnectNames.
func (mr *MockEnvironmentMockRecorder) ConnectNames() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ConnectNames", reflect.TypeOf((*MockEnvironment)(nil).ConnectNames))
}

// GRPCConnection mocks base method.
func (m *MockEnvironment) GRPCConnection(connectionOpts ...common.GRPCOption) (*grpc.ClientConn, error) {
	m.ctrl.T.Helper()
	varargs := []any{}
	for _, a := range connectionOpts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "GRPCConnection", varargs...)
	ret0, _ := ret[0].(*grpc.ClientConn)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GRPCConnection indicates an expected call of GRPCConnection.
func (mr *MockEnvironmentMockRecorder) GRPCConnection(connectionOpts ...any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GRPCConnection", reflect.TypeOf((*MockEnvironment)(nil).GRPCConnection), connectionOpts...)
}

// HTTPClient mocks base method.
func (m *MockEnvironment) HTTPClient(timeout time.Duration, options ...common.HttpClientOption) (common.RoxctlHTTPClient, error) {
	m.ctrl.T.Helper()
	varargs := []any{timeout}
	for _, a := range options {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "HTTPClient", varargs...)
	ret0, _ := ret[0].(common.RoxctlHTTPClient)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// HTTPClient indicates an expected call of HTTPClient.
func (mr *MockEnvironmentMockRecorder) HTTPClient(timeout any, options ...any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]any{timeout}, options...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "HTTPClient", reflect.TypeOf((*MockEnvironment)(nil).HTTPClient), varargs...)
}

// InputOutput mocks base method.
func (m *MockEnvironment) InputOutput() io.IO {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "InputOutput")
	ret0, _ := ret[0].(io.IO)
	return ret0
}

// InputOutput indicates an expected call of InputOutput.
func (mr *MockEnvironmentMockRecorder) InputOutput() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "InputOutput", reflect.TypeOf((*MockEnvironment)(nil).InputOutput))
}

// Logger mocks base method.
func (m *MockEnvironment) Logger() logger.Logger {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Logger")
	ret0, _ := ret[0].(logger.Logger)
	return ret0
}

// Logger indicates an expected call of Logger.
func (mr *MockEnvironmentMockRecorder) Logger() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Logger", reflect.TypeOf((*MockEnvironment)(nil).Logger))
}
