package models

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type User struct {
	ID 			primitive.ObjectID 	`bson:"_id"`
	UserId		string				`json:"userid"`
	Username 	string 				`json:"username"`
	Password 	string 				`json:"password"`
	Phone 		string 				`json:"phone"`
}