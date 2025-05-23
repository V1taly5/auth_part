// Code generated by MockGen. DO NOT EDIT.
// Source: /home/vito/Source/projects/pas/internal/services/auth.go

// Package mockstorage is a generated GoMock package.
package mockstorage

import (
	context "context"
	models "pas/internal/models"
	reflect "reflect"

	"go.uber.org/mock/gomock"
	uuid "github.com/google/uuid"
)

// MockIstorage is a mock of Istorage interface.
type MockIstorage struct {
	ctrl     *gomock.Controller
	recorder *MockIstorageMockRecorder
}

// MockIstorageMockRecorder is the mock recorder for MockIstorage.
type MockIstorageMockRecorder struct {
	mock *MockIstorage
}

// NewMockIstorage creates a new mock instance.
func NewMockIstorage(ctrl *gomock.Controller) *MockIstorage {
	mock := &MockIstorage{ctrl: ctrl}
	mock.recorder = &MockIstorageMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockIstorage) EXPECT() *MockIstorageMockRecorder {
	return m.recorder
}

// CreateAndRevokeRefreshToken mocks base method.
func (m *MockIstorage) CreateAndRevokeRefreshToken(ctx context.Context, tokenData *models.RefreshTokenData, jwtID uuid.UUID) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateAndRevokeRefreshToken", ctx, tokenData, jwtID)
	ret0, _ := ret[0].(error)
	return ret0
}

// CreateAndRevokeRefreshToken indicates an expected call of CreateAndRevokeRefreshToken.
func (mr *MockIstorageMockRecorder) CreateAndRevokeRefreshToken(ctx, tokenData, jwtID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateAndRevokeRefreshToken", reflect.TypeOf((*MockIstorage)(nil).CreateAndRevokeRefreshToken), ctx, tokenData, jwtID)
}

// CreateRefreshToken mocks base method.
func (m *MockIstorage) CreateRefreshToken(arg0 context.Context, arg1 *models.RefreshTokenData) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateRefreshToken", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// CreateRefreshToken indicates an expected call of CreateRefreshToken.
func (mr *MockIstorageMockRecorder) CreateRefreshToken(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateRefreshToken", reflect.TypeOf((*MockIstorage)(nil).CreateRefreshToken), arg0, arg1)
}

// GetRefreshTokenById mocks base method.
func (m *MockIstorage) GetRefreshTokenById(arg0 context.Context, arg1 uuid.UUID) (*models.RefreshTokenData, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetRefreshTokenById", arg0, arg1)
	ret0, _ := ret[0].(*models.RefreshTokenData)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetRefreshTokenById indicates an expected call of GetRefreshTokenById.
func (mr *MockIstorageMockRecorder) GetRefreshTokenById(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetRefreshTokenById", reflect.TypeOf((*MockIstorage)(nil).GetRefreshTokenById), arg0, arg1)
}

// GetUserByID mocks base method.
func (m *MockIstorage) GetUserByID(arg0 context.Context, arg1 uuid.UUID) (*models.User, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetUserByID", arg0, arg1)
	ret0, _ := ret[0].(*models.User)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetUserByID indicates an expected call of GetUserByID.
func (mr *MockIstorageMockRecorder) GetUserByID(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetUserByID", reflect.TypeOf((*MockIstorage)(nil).GetUserByID), arg0, arg1)
}
