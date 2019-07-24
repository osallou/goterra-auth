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

	terrautils "github.com/osallou/goterra-auth/lib/utils"
	terraConfig "github.com/osallou/goterra-lib/lib/config"
	terraUser "github.com/osallou/goterra-lib/lib/user"
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
	Admin    *bool
	Super    *bool
}

// Update updates user info
var Update = func(options Options) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	filter := bson.M{
		"uid": *options.UID,
	}

	var userdb terraUser.User
	err := userCollection.FindOne(ctx, filter).Decode(&userdb)
	if err != nil {
		log.Printf("User not found\n")
		return false
	}

	toUpdate := bson.M{
		"admin":     *options.Admin,
		"superuser": *options.Super,
	}

	if *options.Password != "" {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(*options.Password), bcrypt.DefaultCost)
		if err != nil {
			log.Println(err)
			return false
		}
		toUpdate["password"] = string(hashedPassword)
	}
	if *options.Email != "" {
		toUpdate["email"] = *options.Email
	}

	updateData := bson.M{
		"$set": toUpdate,
	}

	var updatedUser terraUser.User
	err = userCollection.FindOneAndUpdate(ctx, filter, updateData).Decode(&updatedUser)
	if err != nil {
		log.Printf("Error updating user: %s", err)
		return false
	}
	log.Printf("User updated")

	return true
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

	apiKey := terrautils.RandStringBytes(20)

	user := bson.M{
		"uid":      options.UID,
		"email":    options.Email,
		"password": string(hashedPassword),
		"apikey":   apiKey,
		"admin":    options.Admin,
		"super":    options.Super,
	}
	res, err := userCollection.InsertOne(ctx, user)
	id := res.InsertedID
	if err != nil {
		log.Printf("[ERROR] Failed to create user\n")
		return false
	}
	log.Printf("[DEBUG] User created, id:%s, apikey: %s", id, apiKey)
	return true

}

func main() {

	var register bool
	var update bool
	options := Options{}
	options.UID = flag.String("uid", "", "User identifier")
	options.Password = flag.String("password", "", "User password")
	options.Email = flag.String("email", "", "User email")
	options.Admin = flag.Bool("admin", false, "Is administrator?")
	options.Super = flag.Bool("super", false, "Is super user?")
	flag.BoolVar(&register, "register", false, "register a user")
	flag.BoolVar(&update, "update", false, "update user info")
	flag.Parse()
	if *options.UID == "" || *options.Password == "" {
		fmt.Printf("action or uid or password is empty\n")
		os.Exit(1)
	}

	if !register && !update {
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

	if register {
		Register(options)
	} else if update {
		Update(options)
	} else {
		log.Printf("no command\n")
	}
}
