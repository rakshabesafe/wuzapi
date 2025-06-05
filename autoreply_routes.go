package main

import (
	"github.com/gorilla/mux"
	"github.com/justinas/alice"
)

func registerAutoreplyRoutes(s *server, r *mux.Router, c alice.Chain) {
	// Simple Autoreply routes (formerly in /chat/autoreply)
	r.Handle("/chat/autoreply", c.Then(s.AddAutoReply())).Methods("POST")
	r.Handle("/chat/autoreply", c.Then(s.DeleteAutoReply())).Methods("DELETE")
	r.Handle("/chat/autoreply", c.Then(s.GetAutoReplies())).Methods("GET")

	// Mode Autoreply routes (formerly /mode/..., now /autoreply/...)
	r.Handle("/autoreply/mode", c.Then(s.AddModeAutoreply())).Methods("POST")
	r.Handle("/autoreply/mode", c.Then(s.GetModeAutoreplies())).Methods("GET")
	r.Handle("/autoreply/mode", c.Then(s.DeleteModeAutoreply())).Methods("DELETE")

	r.Handle("/autoreply/enablemode", c.Then(s.EnableMode())).Methods("POST")
	r.Handle("/autoreply/disablemode", c.Then(s.DisableMode())).Methods("POST")
	r.Handle("/autoreply/currentmode", c.Then(s.GetCurrentMode())).Methods("GET")
	r.Handle("/autoreply/clearmode", c.Then(s.ClearModes())).Methods("POST")

	// Google Contacts integration routes (already under /autoreply/)
	r.Handle("/autoreply/contactgroupauth", c.Then(s.SetGoogleContactsAuthToken())).Methods("POST")
	r.Handle("/autoreply/contactgroup", c.Then(s.AddContactGroupToMode())).Methods("POST")
	r.Handle("/autoreply/contactgroup", c.Then(s.DeleteContactGroupFromMode())).Methods("DELETE")
}
