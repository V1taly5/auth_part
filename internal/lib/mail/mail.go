package mail

import "log"

type Sender interface {
	SendIPChangeWarning(email, oldIP, newIP string) error
}

type MockEmailSender struct {
	Called bool
}

func NewMockEmailSender() Sender {
	return &MockEmailSender{}
}

func (s *MockEmailSender) SendIPChangeWarning(email, oldIP, newIP string) error {
	log.Printf("[MOCK EMAIL] To: %s, Subject: Security Alert - IP Address Change\n", email)
	log.Printf("[MOCK EMAIL] Body: We detected a new login from IP: %s (previous: %s)\n", newIP, oldIP)
	s.Called = true
	return nil
}
