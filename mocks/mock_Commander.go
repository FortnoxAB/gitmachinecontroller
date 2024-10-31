// Code generated by mockery v2.45.1. DO NOT EDIT.

package mocks

import mock "github.com/stretchr/testify/mock"

// MockCommander is an autogenerated mock type for the Commander type
type MockCommander struct {
	mock.Mock
}

type MockCommander_Expecter struct {
	mock *mock.Mock
}

func (_m *MockCommander) EXPECT() *MockCommander_Expecter {
	return &MockCommander_Expecter{mock: &_m.Mock}
}

// Run provides a mock function with given fields: _a0
func (_m *MockCommander) Run(_a0 string) (string, string, error) {
	ret := _m.Called(_a0)

	if len(ret) == 0 {
		panic("no return value specified for Run")
	}

	var r0 string
	var r1 string
	var r2 error
	if rf, ok := ret.Get(0).(func(string) (string, string, error)); ok {
		return rf(_a0)
	}
	if rf, ok := ret.Get(0).(func(string) string); ok {
		r0 = rf(_a0)
	} else {
		r0 = ret.Get(0).(string)
	}

	if rf, ok := ret.Get(1).(func(string) string); ok {
		r1 = rf(_a0)
	} else {
		r1 = ret.Get(1).(string)
	}

	if rf, ok := ret.Get(2).(func(string) error); ok {
		r2 = rf(_a0)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// MockCommander_Run_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Run'
type MockCommander_Run_Call struct {
	*mock.Call
}

// Run is a helper method to define mock.On call
//   - _a0 string
func (_e *MockCommander_Expecter) Run(_a0 interface{}) *MockCommander_Run_Call {
	return &MockCommander_Run_Call{Call: _e.mock.On("Run", _a0)}
}

func (_c *MockCommander_Run_Call) Run(run func(_a0 string)) *MockCommander_Run_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string))
	})
	return _c
}

func (_c *MockCommander_Run_Call) Return(_a0 string, _a1 string, _a2 error) *MockCommander_Run_Call {
	_c.Call.Return(_a0, _a1, _a2)
	return _c
}

func (_c *MockCommander_Run_Call) RunAndReturn(run func(string) (string, string, error)) *MockCommander_Run_Call {
	_c.Call.Return(run)
	return _c
}

// RunExpectCodes provides a mock function with given fields: _a0, codes
func (_m *MockCommander) RunExpectCodes(_a0 string, codes ...int) (string, int, error) {
	_va := make([]interface{}, len(codes))
	for _i := range codes {
		_va[_i] = codes[_i]
	}
	var _ca []interface{}
	_ca = append(_ca, _a0)
	_ca = append(_ca, _va...)
	ret := _m.Called(_ca...)

	if len(ret) == 0 {
		panic("no return value specified for RunExpectCodes")
	}

	var r0 string
	var r1 int
	var r2 error
	if rf, ok := ret.Get(0).(func(string, ...int) (string, int, error)); ok {
		return rf(_a0, codes...)
	}
	if rf, ok := ret.Get(0).(func(string, ...int) string); ok {
		r0 = rf(_a0, codes...)
	} else {
		r0 = ret.Get(0).(string)
	}

	if rf, ok := ret.Get(1).(func(string, ...int) int); ok {
		r1 = rf(_a0, codes...)
	} else {
		r1 = ret.Get(1).(int)
	}

	if rf, ok := ret.Get(2).(func(string, ...int) error); ok {
		r2 = rf(_a0, codes...)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// MockCommander_RunExpectCodes_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'RunExpectCodes'
type MockCommander_RunExpectCodes_Call struct {
	*mock.Call
}

// RunExpectCodes is a helper method to define mock.On call
//   - _a0 string
//   - codes ...int
func (_e *MockCommander_Expecter) RunExpectCodes(_a0 interface{}, codes ...interface{}) *MockCommander_RunExpectCodes_Call {
	return &MockCommander_RunExpectCodes_Call{Call: _e.mock.On("RunExpectCodes",
		append([]interface{}{_a0}, codes...)...)}
}

func (_c *MockCommander_RunExpectCodes_Call) Run(run func(_a0 string, codes ...int)) *MockCommander_RunExpectCodes_Call {
	_c.Call.Run(func(args mock.Arguments) {
		variadicArgs := make([]int, len(args)-1)
		for i, a := range args[1:] {
			if a != nil {
				variadicArgs[i] = a.(int)
			}
		}
		run(args[0].(string), variadicArgs...)
	})
	return _c
}

func (_c *MockCommander_RunExpectCodes_Call) Return(_a0 string, _a1 int, _a2 error) *MockCommander_RunExpectCodes_Call {
	_c.Call.Return(_a0, _a1, _a2)
	return _c
}

func (_c *MockCommander_RunExpectCodes_Call) RunAndReturn(run func(string, ...int) (string, int, error)) *MockCommander_RunExpectCodes_Call {
	_c.Call.Return(run)
	return _c
}

// RunWithCode provides a mock function with given fields: _a0
func (_m *MockCommander) RunWithCode(_a0 string) (string, string, int, error) {
	ret := _m.Called(_a0)

	if len(ret) == 0 {
		panic("no return value specified for RunWithCode")
	}

	var r0 string
	var r1 string
	var r2 int
	var r3 error
	if rf, ok := ret.Get(0).(func(string) (string, string, int, error)); ok {
		return rf(_a0)
	}
	if rf, ok := ret.Get(0).(func(string) string); ok {
		r0 = rf(_a0)
	} else {
		r0 = ret.Get(0).(string)
	}

	if rf, ok := ret.Get(1).(func(string) string); ok {
		r1 = rf(_a0)
	} else {
		r1 = ret.Get(1).(string)
	}

	if rf, ok := ret.Get(2).(func(string) int); ok {
		r2 = rf(_a0)
	} else {
		r2 = ret.Get(2).(int)
	}

	if rf, ok := ret.Get(3).(func(string) error); ok {
		r3 = rf(_a0)
	} else {
		r3 = ret.Error(3)
	}

	return r0, r1, r2, r3
}

// MockCommander_RunWithCode_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'RunWithCode'
type MockCommander_RunWithCode_Call struct {
	*mock.Call
}

// RunWithCode is a helper method to define mock.On call
//   - _a0 string
func (_e *MockCommander_Expecter) RunWithCode(_a0 interface{}) *MockCommander_RunWithCode_Call {
	return &MockCommander_RunWithCode_Call{Call: _e.mock.On("RunWithCode", _a0)}
}

func (_c *MockCommander_RunWithCode_Call) Run(run func(_a0 string)) *MockCommander_RunWithCode_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string))
	})
	return _c
}

func (_c *MockCommander_RunWithCode_Call) Return(_a0 string, _a1 string, _a2 int, _a3 error) *MockCommander_RunWithCode_Call {
	_c.Call.Return(_a0, _a1, _a2, _a3)
	return _c
}

func (_c *MockCommander_RunWithCode_Call) RunAndReturn(run func(string) (string, string, int, error)) *MockCommander_RunWithCode_Call {
	_c.Call.Return(run)
	return _c
}

// NewMockCommander creates a new instance of MockCommander. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMockCommander(t interface {
	mock.TestingT
	Cleanup(func())
}) *MockCommander {
	mock := &MockCommander{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
