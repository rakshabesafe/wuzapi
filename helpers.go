package main

import (
	"fmt"
	"github.com/rs/zerolog/log"
)

// Find takes a slice of strings and looks for an element in it. If found it will
// return its key/index, otherwise it will return -1 and a bool of false.
func Find(slice []string, val string) (int, bool) {
	for i, item := range slice {
		if item == val {
			return i, true
		}
	}
	return -1, false
}

// Values struct holds key-value pairs, typically for user information.
type Values struct {
	m map[string]string
}

// Get retrieves a value by key from the Values struct.
func (v Values) Get(key string) string {
	return v.m[key]
}

// Update entry in User map
// This version is type-safe with the Values struct.
func updateUserInfo(v Values, key string, value string) Values {
	// Ensure the map is initialized if it's nil, which can happen if Values is zero-initialized.
	if v.m == nil {
		v.m = make(map[string]string)
	}
	log.Debug().Str("field", key).Str("value", value).Msg("User info updated")
	v.m[key] = value
	return v
}

// webhook for regular messages
func callHook(myurl string, payload map[string]string, id string) {
	log.Info().Str("url", myurl).Msg("Sending POST to client " + id)

	// Log the payload map
	log.Debug().Msg("Payload:")
	for key, value := range payload {
		log.Debug().Str(key, value).Msg("")
	}

	client := clientManager.GetHTTPClient(id)

	_, err := client.R().SetFormData(payload).Post(myurl)
	if err != nil {
		log.Debug().Str("error", err.Error())
	}
}

// webhook for messages with file attachments
func callHookFile(myurl string, payload map[string]string, id string, file string) error {
	log.Info().Str("file", file).Str("url", myurl).Msg("Sending POST")

	client := clientManager.GetHTTPClient(id)

	// Create final payload map
	finalPayload := make(map[string]string)
	for k, v := range payload {
		finalPayload[k] = v
	}

	finalPayload["file"] = file

	log.Debug().Interface("finalPayload", finalPayload).Msg("Final payload to be sent")

	resp, err := client.R().
		SetFiles(map[string]string{
			"file": file,
		}).
		SetFormData(finalPayload).
		Post(myurl)

	if err != nil {
		log.Error().Err(err).Str("url", myurl).Msg("Failed to send POST request")
		return fmt.Errorf("failed to send POST request: %w", err)
	}

	log.Debug().Interface("payload", finalPayload).Msg("Payload sent to webhook")
	log.Info().Int("status", resp.StatusCode()).Str("body", string(resp.Body())).Msg("POST request completed")

	return nil
}
