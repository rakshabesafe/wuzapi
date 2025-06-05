package main

// AuthTokenRequest defines the structure for the /autoreply/contactgroupauth endpoint
type AuthTokenRequest struct {
	AuthToken string `json:"AuthToken"`
}

// ContactGroupRequest defines the structure for the /autoreply/contactgroup endpoint
type ContactGroupRequest struct {
	ModeName  string `json:"ModeName"`
	GroupName string `json:"GroupName"`
	Message   string `json:"Message"`
}

// ContactGroupDeleteRequest defines the structure for the DELETE /autoreply/contactgroup endpoint
type ContactGroupDeleteRequest struct {
	ModeName  string `json:"ModeName"`
	GroupName string `json:"GroupName"`
}

// Structs for Google People API responses
type GoogleContactGroup struct {
	ResourceName  string `json:"resourceName"`
	Name          string `json:"name"`
	FormattedName string `json:"formattedName"`
	MemberCount   int    `json:"memberCount"`
}

type GoogleContactGroupListResponse struct {
	ContactGroups []GoogleContactGroup `json:"contactGroups"`
	NextPageToken string             `json:"nextPageToken"`
}

type GooglePersonName struct {
	DisplayName string `json:"displayName"`
}

type GooglePhoneNumber struct {
	Value         string `json:"value"`
	CanonicalForm string `json:"canonicalForm"`
}

type GoogleContactGroupMembership struct {
	ContactGroupResourceName string `json:"contactGroupResourceName"`
}

type GoogleMembership struct {
	ContactGroupMembership GoogleContactGroupMembership `json:"contactGroupMembership"`
}

type GooglePerson struct {
	ResourceName string              `json:"resourceName"`
	Names        []GooglePersonName    `json:"names"`
	PhoneNumbers []GooglePhoneNumber   `json:"phoneNumbers"`
	Memberships  []GoogleMembership    `json:"memberships"`
}

type GoogleConnectionsListResponse struct {
	Connections   []GooglePerson `json:"connections"`
	NextPageToken string       `json:"nextPageToken"`
	TotalItems    int          `json:"totalItems"`
}

type GoogleApiErrorDetail struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Status  string `json:"status"`
}

type GoogleApiError struct {
	Error GoogleApiErrorDetail `json:"error"`
}
