package main

import "time"

// Structs for simple Autoreply functionality (formerly in handlers.go)
type AutoReplyRequest struct {
	Phone string `json:"Phone"`
	Body  string `json:"Body"`
}

type AutoReplyEntry struct {
	Phone      string     `json:"phone"`
	Body       string     `json:"body"`
	LastSentAt *time.Time `json:"last_sent_at,omitempty"`
}

type DeleteAutoReplyRequest struct {
	Phone string `json:"Phone"`
}

// Structs for Mode Autoreply functionality (formerly in handlers.go)
type ModeAutoreplyRequest struct {
	ModeName string `json:"ModeName"`
	Phone    string `json:"Phone"`
	Message  string `json:"Message"`
}

type ModeAutoreplyDeleteRequest struct {
	ModeName string `json:"ModeName"`
	Phone    string `json:"Phone,omitempty"`
}

type EnableModeRequest struct {
	ModeName string `json:"ModeName"`
}

type DisableModeRequest struct {
	ModeName string `json:"ModeName"`
}

type ModeAutoreplyEntry struct {
	ModeName string `json:"ModeName"`
	Phone    string `json:"Phone"`
	Message  string `json:"Message"`
}

// Google Contacts related structs have been moved to google_contacts_types.go
