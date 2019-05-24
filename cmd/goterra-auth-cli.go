package main

/*
 TODO auth user against ldap, openid, ...
*/

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"golang.org/x/crypto/bcrypt"

	"go.mongodb.org/mongo-driver/bson"
	mongo "go.mongodb.org/mongo-driver/mongo"
	mongoOptions "go.mongodb.org/mongo-driver/mongo/options"

	terraConfig "github.com/osallou/goterra-auth/lib/config"
)

// Version of server
var Version string

var mongoClient mongo.Client
var userCollection *mongo.Collection

// Options used at command line
type Options struct {
	UID      *string
	Email    *string
	Password *string
}

// Register manages authentication
var Register = func(options Options) bool {
	// config := terraConfig.LoadConfig()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(*options.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Println(err)
		return false
	}

	user := bson.M{
		"uid":      options.UID,
		"email":    options.Email,
		"password": string(hashedPassword),
	}
	res, err := userCollection.InsertOne(ctx, user)
	id := res.InsertedID
	if err != nil {
		log.Printf("[ERROR] Failed to create user\n")
		return false
	}
	log.Printf("[DEBUG] User created, id:%s", id)
	return true

}

func main() {

	var register bool
	options := Options{}
	options.UID = flag.String("uid", "", "User identifier")
	options.Password = flag.String("password", "", "User password")
	options.Email = flag.String("email", "", "User email")
	flag.BoolVar(&register, "register", false, "register a user")
	flag.Parse()
	if *options.UID == "" || *options.Password == "" {
		fmt.Printf("action or uid or password is empty\n")
		os.Exit(1)
	}

	if !register {
		fmt.Printf("invalid action\n")
		os.Exit(1)
	}

	config := terraConfig.LoadConfig()
	mongoClient, err := mongo.NewClient(mongoOptions.Client().ApplyURI(config.Mongo.URL))
	if err != nil {
		log.Printf("[ERROR] Failed to connect to mongo server %s, %v\n", config.Mongo.URL, err)
		os.Exit(1)
	}
	ctx, cancelMongo := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelMongo()

	err = mongoClient.Connect(ctx)
	if err != nil {
		log.Printf("[ERROR] Failed to connect to mongo server %s\n", config.Mongo.URL)
		os.Exit(1)
	}

	userCollection = mongoClient.Database(config.Mongo.DB).Collection("users")

	Register(options)
}
