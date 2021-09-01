package controllers

import (
	"context"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"log"
	"net/http"
	"testJunior/database"
	helper "testJunior/helpers"
	"testJunior/models"
	"time"
)

var userCollection = database.OpenCollection(database.Client, "user")
var validate = validator.New()

//Регистрация пользователя
func SignUp(c *gin.Context) {
	var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
	var user models.User

	if err := c.BindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	validationErr := validate.Struct(user)
	if validationErr != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": validationErr.Error()})
		return
	}

	count, err := userCollection.CountDocuments(ctx, bson.M{"username": user.Username})
	defer cancel()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "error occured while checking for the email"})
		log.Panic(err)
		return
	}

	password := helper.HashPassword(user.Password)
	user.Password = password

	count, err = userCollection.CountDocuments(ctx, bson.M{"phone": user.Phone})
	defer cancel()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "error occured while checking for the phone number"})
		log.Panic(err)
		return
	}

	if count > 0 {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "this phone number already exists"})
		return
	}

	user.ID = primitive.NewObjectID()
	user.UserId = user.ID.Hex()

	resultInsertionNumber, insertErr := userCollection.InsertOne(ctx, user)
	if insertErr != nil {
		msg := fmt.Sprintf("User item was not created")
		c.JSON(http.StatusInternalServerError, gin.H{"error": msg})
		return
	}
	defer cancel()

	c.JSON(http.StatusOK, resultInsertionNumber)
}

//Аутентификация пользователя
func Login(c *gin.Context) {
	var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
	var user models.User
	var foundUser models.User

	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusUnprocessableEntity, "Invalid json provided")
		return
	}

	err := userCollection.FindOne(ctx, bson.M{"username": user.Username}).Decode(&foundUser)
	defer cancel()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "username or passowrd is incorrect"})
		return
	}

	passwordIsValid, msg := helper.VerifyPassword(user.Password, foundUser.Password)
	defer cancel()
	if passwordIsValid != true {
		c.JSON(http.StatusInternalServerError, gin.H{"error": msg})
		return
	}

	ad, err := helper.CreateToken(foundUser.UserId)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, err.Error())
		return
	}

	saveErr := CreateAuth(ad)
	if saveErr != nil {
		c.JSON(http.StatusUnprocessableEntity, saveErr.Error())
		return
	}

	tokens := map[string]string{
		"access_token":  ad.AccessToken,
		"refresh_token": ad.RefreshToken,
	}

	c.JSON(http.StatusOK, tokens)
}

//Обработчик Refresh запроса
func Refresh(c *gin.Context) {
	tokenAuth, err := helper.ExtractTokenMetadata(c.Request)
	if err != nil {
		c.JSON(http.StatusUnauthorized, err.Error())
		c.Abort()
		return
	}

	if tokenAuth.Expired {
		err = DeleteOldAuth()
		if err != nil {
			c.JSON(http.StatusUnauthorized, err.Error())
			c.Abort()
			return
		}
	}

	var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)

	filter := bson.D{{"tuuid", tokenAuth.TUuid}}

	var rawAd map[string]interface{}
	err = userCollection.FindOne(ctx, filter).Decode(&rawAd)
	if err != nil {
		// ErrNoDocuments means that the filter did not match any documents in
		//the collection.
		if err == mongo.ErrNoDocuments {
			return
		}
		log.Fatal(err)
	}
	count, err := userCollection.DeleteOne(ctx,	filter)
	if err != nil {
		log.Panic(err)
		return
	}

	defer cancel()

	if count.DeletedCount != 1 {
		c.JSON(http.StatusUnauthorized, "Refresh token expired")
		return
	}

	ad, err := helper.CreateToken(rawAd["userid"].(string))
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, err.Error())
		return
	}

	saveErr := CreateAuth(ad)
	if saveErr != nil {
		c.JSON(http.StatusUnprocessableEntity, saveErr.Error())
		return
	}

	tokens := map[string]string{
		"access_token":  ad.AccessToken,
		"refresh_token": ad.RefreshToken,
	}

	c.JSON(http.StatusCreated, tokens)
}

//Удаляет просроченные документы из коллекции
func DeleteOldAuth() error {
	var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)

	var now primitive.DateTime
	now = primitive.NewDateTimeFromTime(time.Now())

	filter := bson.D{{"expires", bson.D{{"$lte", now}}}}

	_, err := userCollection.DeleteMany(
		ctx,
		filter,
	)
	defer cancel()

	if err != nil {
		log.Panic(err)
		return err
	}

	return nil
}

//Добавляет документ в коллекцию
func CreateAuth(ad *helper.AccessDetails) error {
	var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)

	toTime := time.Unix(ad.RtExpires, 0)
	expires := primitive.NewDateTimeFromTime(toTime)

	var tUuidRecord primitive.D
	tUuidRecord = append(tUuidRecord, bson.E{Key: "tuuid", Value: ad.TUuid})
	tUuidRecord = append(tUuidRecord, bson.E{Key: "rthash", Value: ad.RTHash})
	tUuidRecord = append(tUuidRecord, bson.E{Key: "userid", Value: ad.UserId})
	tUuidRecord = append(tUuidRecord, bson.E{Key: "expires", Value: expires})
	_, err := userCollection.InsertOne(ctx, tUuidRecord)

	defer cancel()

	if err != nil {
		log.Panic(err)
		return err
	}

	return nil
}

//Ищет документ в коллекции
func FetchAuth(authD *helper.AccessDetails) error {
	var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)

	var ad map[string]interface{}
	filter := bson.D{{"tuuid", authD.TUuid}}
	err := userCollection.FindOne(ctx,filter).Decode(&ad)
	if err != nil {
		log.Fatal(err)
	}

	defer cancel()

	if ad["userid"].(string) != authD.UserId {
		return fmt.Errorf("unauthorized")
	}

	return nil
}