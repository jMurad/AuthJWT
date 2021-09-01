package database

import (
	"context"
	"fmt"
	"github.com/joho/godotenv"
	"log"
	"os"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

//Подключение к серверу БД
func DBinstance() *mongo.Client {
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	MongoDb := os.Getenv("MONGODB_URL")

	client, err := mongo.NewClient(options.Client().ApplyURI(MongoDb))
	if err != nil {
		log.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = client.Connect(ctx)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Connected to MongoDB!")

	return client
}

//Создает базу данных
func Database() *mongo.Database {
	err := godotenv.Load(".env")
	MongoDb := os.Getenv("MONGODB_URL")

	opt := options.Client().ApplyURI(MongoDb)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, opt)
	if err != nil {
		log.Fatal(err.Error())
	}

	return client.Database("cluster1")
}

//Экземпляр базы данных
var Client *mongo.Client = DBinstance()

//Устанавливает соединение с коллекцией в базе данных
func OpenCollection(client *mongo.Client, collectionName string) *mongo.Collection {
	var collection *mongo.Collection = client.Database("cluster0").Collection(collectionName)
	return collection
}