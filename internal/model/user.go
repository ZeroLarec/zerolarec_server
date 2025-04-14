package model

type User struct {
	UserID string
	Login  string
}

func NewUser(login string) *User {
	return &User{
		Login: login,
	}
}
