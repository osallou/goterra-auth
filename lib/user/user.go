package goterrauser

// User represents a user in database
type User struct {
	UID        string          `json:"uid"`
	Password   string          `json:"password"`
	Groups     []string        `json:"groups"`
	Email      string          `json:"email"`
	Active     bool            `json:"active"`
	Admin      bool            `json:"admin"`
	APIKey     string          `json:"apikey"`
	Namespaces map[string]bool // map of namespace names, if true user is owner of namespace else only a member
}

// Namespace represents a namespace
type Namespace struct {
	ID string
}
