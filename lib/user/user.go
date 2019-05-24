package goterrauser

// User represents a user in database
type User struct {
	UID      string   `json:"uid"`
	Password string   `json:"password"`
	Groups   []string `json:"groups"`
	Email    string   `json:"email"`
	Active   bool     `json:"active"`
	Admin    bool     `json:"admin"`
	APIKey   string   `json:"apikey"`
}
