// Code generated by mockery. DO NOT EDIT.

package mocks

import mock "github.com/stretchr/testify/mock"

// NeedLeaderElectionNotification is an autogenerated mock type for the NeedLeaderElectionNotification type
type NeedLeaderElectionNotification struct {
	mock.Mock
}

// OnElectedLeader provides a mock function with no fields
func (_m *NeedLeaderElectionNotification) OnElectedLeader() {
	_m.Called()
}

// NewNeedLeaderElectionNotification creates a new instance of NeedLeaderElectionNotification. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewNeedLeaderElectionNotification(t interface {
	mock.TestingT
	Cleanup(func())
}) *NeedLeaderElectionNotification {
	mock := &NeedLeaderElectionNotification{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
