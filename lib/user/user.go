package goterrauser

// User represents a user in database
type User struct {
	UID      string
	Password string
	Groups   []string
	Email    string
	Active   bool
	Admin    bool
}
