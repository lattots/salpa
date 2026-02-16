package models

type User interface {
	GetID() string
	GetEmail() string
}
