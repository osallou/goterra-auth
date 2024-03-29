package main

/*
 TODO auth user against ldap, openid, ...
*/

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/rs/cors"
	"github.com/streadway/amqp"
	"go.mongodb.org/mongo-driver/bson"
	mongo "go.mongodb.org/mongo-driver/mongo"
	mongoOptions "go.mongodb.org/mongo-driver/mongo/options"

	terraUtils "github.com/osallou/goterra-auth/lib/utils"
	terraConfig "github.com/osallou/goterra-lib/lib/config"
	terraModel "github.com/osallou/goterra-lib/lib/model"
	terraToken "github.com/osallou/goterra-lib/lib/token"
	terraUser "github.com/osallou/goterra-lib/lib/user"

	oidc "github.com/coreos/go-oidc"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Openid
var openidctx context.Context
var googleProvider *oidc.Provider
var aaiProvider *oidc.Provider

// Version of server
var Version string

var mongoClient mongo.Client
var userCollection *mongo.Collection

// userUpdatedMessage sends a message to rabbitmq exchange
func userUpdatedMessage(uid string, user terraUser.User) error {
	if os.Getenv("GOT_MOCK_AMQP") == "1" {
		return nil
	}
	config := terraConfig.LoadConfig()
	if config.Amqp == "" {
		fmt.Printf("[ERROR] no amqp defined\n")
		return fmt.Errorf("No AMQP config found")
	}
	conn, err := amqp.Dial(config.Amqp)
	if err != nil {
		log.Error().Msgf("[ERROR] failed to send message for user %s: %s\n", uid, err)
		return err
	}
	defer conn.Close()

	ch, err := conn.Channel()
	if err != nil {
		log.Error().Msgf("[ERROR] failed to connect to amqp\n")
		return err
	}

	err = ch.ExchangeDeclare(
		"gotevent", // name
		"fanout",   // type
		true,       // durable
		false,      // auto-deleted
		false,      // internal
		false,      // no-wait
		nil,        // arguments
	)
	if err != nil {
		log.Error().Msgf("[ERROR] failed to connect to open exchange\n")
		return err
	}

	userJSON, _ := json.Marshal(user)

	msg := &terraModel.UserAction{Action: "user_update", UID: uid, Data: string(userJSON)}
	body, _ := json.Marshal(msg)
	err = ch.Publish(
		"gotevent", // exchange
		"",         // routing key
		false,      // mandatory
		false,      // immediate
		amqp.Publishing{
			ContentType: "text/plain",
			Body:        []byte(body),
		})
	if err != nil {
		log.Error().Msgf("[ERROR] failed to send message\n")
		return err
	}
	return nil
}

//userCreatedMessage sends a message to rabbitmq exchange
func userCreatedMessage(uid string, kind string) error {
	if os.Getenv("GOT_MOCK_AMQP") == "1" {
		return nil
	}
	config := terraConfig.LoadConfig()
	if config.Amqp == "" {
		fmt.Printf("[ERROR] no amqp defined\n")
		return fmt.Errorf("No AMQP config found")
	}
	conn, err := amqp.Dial(config.Amqp)
	if err != nil {
		log.Error().Msgf("[ERROR] failed to send message for user %s: %s\n", uid, err)
		return err
	}
	defer conn.Close()

	ch, err := conn.Channel()
	if err != nil {
		log.Error().Msgf("[ERROR] failed to connect to amqp\n")
		return err
	}

	err = ch.ExchangeDeclare(
		"gotevent", // name
		"fanout",   // type
		true,       // durable
		false,      // auto-deleted
		false,      // internal
		false,      // no-wait
		nil,        // arguments
	)
	if err != nil {
		log.Error().Msgf("[ERROR] failed to connect to open exchange\n")
		return err
	}

	msg := &terraModel.UserAction{Action: "user_create", UID: uid, Data: kind}
	body, _ := json.Marshal(msg)
	err = ch.Publish(
		"gotevent", // exchange
		"",         // routing key
		false,      // mandatory
		false,      // immediate
		amqp.Publishing{
			ContentType: "text/plain",
			Body:        []byte(body),
		})
	if err != nil {
		log.Error().Msgf("[ERROR] failed to send message\n")
		return err
	}
	return nil
}

// CheckTokenForDeployment checks JWT token
func CheckTokenForDeployment(authToken string) (user terraUser.User, err error) {
	// config := terraConfig.LoadConfig()

	user = terraUser.User{}
	err = nil

	tokenStr := strings.Replace(authToken, "Bearer", "", -1)
	tokenStr = strings.TrimSpace(tokenStr)

	msg, msgErr := terraToken.FernetDecode([]byte(tokenStr))
	if msgErr != nil {
		log.Debug().Msg("failed to decode token")
		return user, msgErr
	}
	json.Unmarshal(msg, &user)

	return user, err
}

// HomeHandler manages base entrypoint
var HomeHandler = func(w http.ResponseWriter, r *http.Request) {
	resp := map[string]interface{}{"version": Version, "message": "ok"}
	w.Header().Add("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// Claims contains JWT claims
type Claims struct {
	UID   string `json:"uid"`
	Email string `json:"email"`
	// Namespaces map[string]bool `json:"namespaces"`
	jwt.StandardClaims
}

// LoginData contains user credentials
type LoginData struct {
	UID      string `json:"uid"`
	Password string `json:"password"`
}

// RegisterHandler adds a new user
var RegisterHandler = func(w http.ResponseWriter, r *http.Request) {

	allowSelfRegister := os.Getenv("GOT_FEATURE_SELF_REGISTER")
	doAllowSelfRegister := false
	if allowSelfRegister == "1" {
		doAllowSelfRegister = true
	}

	data := &terraUser.User{}
	json.NewDecoder(r.Body).Decode(data)

	if data.UID == "" || data.Password == "" {
		w.WriteHeader(http.StatusForbidden)
		w.Header().Add("Content-Type", "application/json")
		respError := map[string]interface{}{"message": "invalid data, UID and password are mandatory"}
		json.NewEncoder(w).Encode(respError)
		return
	}
	isLogged := false
	loggedUser, err := CheckTokenForDeployment(r.Header.Get("Authorization"))
	if err != nil {
		isLogged = false
		if !doAllowSelfRegister {
			w.WriteHeader(http.StatusForbidden)
			w.Header().Add("Content-Type", "application/json")
			respError := map[string]interface{}{"message": "invalid token"}
			json.NewEncoder(w).Encode(respError)
			return
		}
	} else {
		if !loggedUser.Admin {
			w.WriteHeader(http.StatusForbidden)
			w.Header().Add("Content-Type", "application/json")
			respError := map[string]interface{}{"message": "not allowed to create user, admin only"}
			json.NewEncoder(w).Encode(respError)
			return
		}
		isLogged = true
	}

	filter := bson.M{"uid": data.UID}
	userInDb := terraUser.User{}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err = userCollection.FindOne(ctx, filter).Decode(&userInDb)
	if err != mongo.ErrNoDocuments {
		w.WriteHeader(http.StatusForbidden)
		w.Header().Add("Content-Type", "application/json")
		respError := map[string]interface{}{"message": "user already exists"}
		json.NewEncoder(w).Encode(respError)
	}

	data.APIKey = terraUtils.RandStringBytes(20)
	if !isLogged || (isLogged && !loggedUser.Admin) {
		data.Admin = false
		data.SuperUser = false
	}
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(data.Password), bcrypt.DefaultCost)
	data.Password = string(hashedPassword)

	userCreatedMessage(data.UID, data.Kind)

	res, err := userCollection.InsertOne(ctx, data)
	id := res.InsertedID
	w.Header().Add("Content-Type", "application/json")
	resp := map[string]interface{}{"id": id, "apikey": data.APIKey}
	json.NewEncoder(w).Encode(resp)
}

// APIData is message for auth service url /api/auth
type APIData struct {
	Key string `json:"key"`
}

// AuthData is result struct for authentication with user data and an authentication token
type AuthData struct {
	User  terraUser.User `json:"user"`
	Token string         `json:"token"`
}

// APIKeyHandler checks user api key and returns user info
var APIKeyHandler = func(w http.ResponseWriter, r *http.Request) {
	// config := terraConfig.LoadConfig()
	apiKey := ""
	tokenUser, tokenErr := CheckTokenForDeployment(r.Header.Get("Authorization"))
	if tokenErr == nil {
		apiKey = tokenUser.APIKey
	} else {
		apiKey = r.Header.Get("X-API-Key")
		if apiKey == "" {
			w.WriteHeader(http.StatusForbidden)
			w.Header().Add("Content-Type", "application/json")
			respError := map[string]interface{}{"message": "invalid data"}
			json.NewEncoder(w).Encode(respError)
			return
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	user := terraUser.User{}

	//filter := bson.M{"apikey": data.Key}
	filter := bson.M{"apikey": apiKey}
	err := userCollection.FindOne(ctx, filter).Decode(&user)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		w.Header().Add("Content-Type", "application/json")
		respError := map[string]interface{}{"message": "user not found"}
		json.NewEncoder(w).Encode(respError)
		return
	}
	user.Password = ""
	userJSON, _ := json.Marshal(user)
	token, tokenErr := terraToken.FernetEncode(userJSON)
	if tokenErr != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Add("Content-Type", "application/json")
		respError := map[string]interface{}{"message": fmt.Sprintf("failed to create token: %s", tokenErr)}
		json.NewEncoder(w).Encode(respError)
		return
	}
	authData := AuthData{User: user, Token: string(token)}

	w.Header().Add("Content-Type", "application/json")
	json.NewEncoder(w).Encode(authData)
}

//UsersHandler get all users
var UsersHandler = func(w http.ResponseWriter, r *http.Request) {
	user, err := CheckTokenForDeployment(r.Header.Get("Authorization"))
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		w.Header().Add("Content-Type", "application/json")
		respError := map[string]interface{}{"message": "invalid token"}
		json.NewEncoder(w).Encode(respError)
		return
	}
	if !user.Admin {
		w.WriteHeader(http.StatusForbidden)
		w.Header().Add("Content-Type", "application/json")
		respError := map[string]interface{}{"message": "admin users only"}
		json.NewEncoder(w).Encode(respError)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	users := make([]terraUser.User, 0)
	filter := bson.M{}
	cursor, err := userCollection.Find(ctx, filter)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		w.Header().Add("Content-Type", "application/json")
		respError := map[string]interface{}{"message": "no user found"}
		json.NewEncoder(w).Encode(respError)
		return
	}
	for cursor.Next(ctx) {
		var userdb terraUser.User
		cursor.Decode(&userdb)
		userdb.Password = "*****"
		users = append(users, userdb)
	}

	w.Header().Add("Content-Type", "application/json")
	resp := map[string]interface{}{"users": users}
	json.NewEncoder(w).Encode(resp)
}

//UserHandler get user info
var UserHandler = func(w http.ResponseWriter, r *http.Request) {
	user, err := CheckTokenForDeployment(r.Header.Get("Authorization"))
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		w.Header().Add("Content-Type", "application/json")
		respError := map[string]interface{}{"message": "invalid token"}
		json.NewEncoder(w).Encode(respError)
		return
	}
	vars := mux.Vars(r)
	userID := vars["id"]

	if !user.Admin && user.UID != userID {
		w.WriteHeader(http.StatusForbidden)
		w.Header().Add("Content-Type", "application/json")
		respError := map[string]interface{}{"message": "admin or user only"}
		json.NewEncoder(w).Encode(respError)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	userdb := terraUser.User{}
	filter := bson.M{
		"uid": userID,
	}
	err = userCollection.FindOne(ctx, filter).Decode(&userdb)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		w.Header().Add("Content-Type", "application/json")
		respError := map[string]interface{}{"message": "no user found"}
		json.NewEncoder(w).Encode(respError)
		return
	}
	userdb.Password = "*****"

	w.Header().Add("Content-Type", "application/json")
	resp := map[string]interface{}{"user": userdb}
	json.NewEncoder(w).Encode(resp)
}

// PasswordData is expected message to update user password
type PasswordData struct {
	Password string `json:"password"`
}

//UserPasswordUpdateHandler update user password
var UserPasswordUpdateHandler = func(w http.ResponseWriter, r *http.Request) {
	user, err := CheckTokenForDeployment(r.Header.Get("Authorization"))
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		w.Header().Add("Content-Type", "application/json")
		respError := map[string]interface{}{"message": "invalid token"}
		json.NewEncoder(w).Encode(respError)
		return
	}
	vars := mux.Vars(r)
	userID := vars["id"]

	if !user.Admin && user.UID != userID {
		w.WriteHeader(http.StatusForbidden)
		w.Header().Add("Content-Type", "application/json")
		respError := map[string]interface{}{"message": "admin or user only"}
		json.NewEncoder(w).Encode(respError)
		return
	}

	data := &PasswordData{}
	err = json.NewDecoder(r.Body).Decode(data)
	if err != nil {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		respError := map[string]interface{}{"message": "failed to decode message"}
		json.NewEncoder(w).Encode(respError)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	userdb := terraUser.User{}
	filter := bson.M{
		"uid": userID,
	}
	err = userCollection.FindOne(ctx, filter).Decode(&userdb)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		w.Header().Add("Content-Type", "application/json")
		respError := map[string]interface{}{"message": "no user found"}
		json.NewEncoder(w).Encode(respError)
		return
	}

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(data.Password), bcrypt.DefaultCost)
	userdb.Password = string(hashedPassword)

	newUser := bson.M{
		"$set": userdb,
	}
	userCollection.FindOneAndUpdate(ctx, filter, newUser)
	userdb.Password = "*****"
	w.Header().Add("Content-Type", "application/json")
	resp := map[string]interface{}{"user": userdb}
	json.NewEncoder(w).Encode(resp)
}

//UserUpdateHandler update user info
var UserUpdateHandler = func(w http.ResponseWriter, r *http.Request) {
	user, err := CheckTokenForDeployment(r.Header.Get("Authorization"))
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		w.Header().Add("Content-Type", "application/json")
		respError := map[string]interface{}{"message": "invalid token"}
		json.NewEncoder(w).Encode(respError)
		return
	}
	vars := mux.Vars(r)
	userID := vars["id"]

	if !user.Admin && user.UID != userID {
		w.WriteHeader(http.StatusForbidden)
		w.Header().Add("Content-Type", "application/json")
		respError := map[string]interface{}{"message": "admin or user only"}
		json.NewEncoder(w).Encode(respError)
		return
	}

	data := &terraUser.User{}
	err = json.NewDecoder(r.Body).Decode(data)
	if err != nil {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		respError := map[string]interface{}{"message": "failed to decode message"}
		json.NewEncoder(w).Encode(respError)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	userdb := terraUser.User{}
	filter := bson.M{
		"uid": userID,
	}
	err = userCollection.FindOne(ctx, filter).Decode(&userdb)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		w.Header().Add("Content-Type", "application/json")
		respError := map[string]interface{}{"message": "no user found"}
		json.NewEncoder(w).Encode(respError)
		return
	}

	userdb.Email = data.Email
	userdb.SSHPubKey = data.SSHPubKey
	userdb.APIKey = data.APIKey

	if user.Admin {
		userdb.Admin = data.Admin
		userdb.SuperUser = data.SuperUser
	}

	newUser := bson.M{
		"$set": userdb,
	}
	userCollection.FindOneAndUpdate(ctx, filter, newUser)
	userdb.Password = "*****"

	userUpdatedMessage(userID, userdb)

	w.Header().Add("Content-Type", "application/json")
	resp := map[string]interface{}{"user": userdb}
	json.NewEncoder(w).Encode(resp)
}

// TokenRenewHandler checks token and create a new one
var TokenRenewHandler = func(w http.ResponseWriter, r *http.Request) {
	user, err := CheckTokenForDeployment(r.Header.Get("Authorization"))
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		w.Header().Add("Content-Type", "application/json")
		respError := map[string]interface{}{"message": "invalid token"}
		json.NewEncoder(w).Encode(respError)
		return
	}
	user.Password = "*****"
	userJSON, _ := json.Marshal(user)
	token, tokenErr := terraToken.FernetEncode(userJSON)
	if tokenErr != nil {
		log.Error().Str("uid", user.UID).Msgf("Token renew error: %s", tokenErr)
		w.WriteHeader(http.StatusForbidden)
		w.Header().Add("Content-Type", "application/json")
		respError := map[string]interface{}{"message": "failed to renew token"}
		json.NewEncoder(w).Encode(respError)
		return
	}
	resp := make(map[string]string)
	resp["token"] = string(token)
	w.Header().Add("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// MeHandler gets user info
var MeHandler = func(w http.ResponseWriter, r *http.Request) {
	user, err := CheckTokenForDeployment(r.Header.Get("Authorization"))
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		w.Header().Add("Content-Type", "application/json")
		respError := map[string]interface{}{"message": "invalid token"}
		json.NewEncoder(w).Encode(respError)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	me := terraUser.User{}
	filter := bson.M{"uid": user.UID}
	err = userCollection.FindOne(ctx, filter).Decode(&me)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		w.Header().Add("Content-Type", "application/json")
		respError := map[string]interface{}{"message": "user not found"}
		json.NewEncoder(w).Encode(respError)
		return
	}

	me.Password = "*****"

	w.Header().Add("Content-Type", "application/json")
	json.NewEncoder(w).Encode(me)
}

// LoginHandler manages authentication
var LoginHandler = func(w http.ResponseWriter, r *http.Request) {
	// config := terraConfig.LoadConfig()
	data := &LoginData{}
	err := json.NewDecoder(r.Body).Decode(data)
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		w.Header().Add("Content-Type", "application/json")
		respError := map[string]interface{}{"message": "invalid data"}
		json.NewEncoder(w).Encode(respError)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	user := terraUser.User{}
	filter := bson.M{"uid": data.UID}
	err = userCollection.FindOne(ctx, filter).Decode(&user)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		w.Header().Add("Content-Type", "application/json")
		respError := map[string]interface{}{"message": "user not found"}
		json.NewEncoder(w).Encode(respError)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(data.Password))
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		w.Header().Add("Content-Type", "application/json")
		respError := map[string]interface{}{"message": "invalid password"}
		json.NewEncoder(w).Encode(respError)
		return
	}

	userJSON, _ := json.Marshal(user)
	token, tokenErr := terraToken.FernetEncode(userJSON)
	if tokenErr != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Add("Content-Type", "application/json")
		respError := map[string]interface{}{"message": "token creation error"}
		json.NewEncoder(w).Encode(respError)
		return
	}

	resp := make(map[string]interface{})
	resp["token"] = string(token)
	resp["apikey"] = user.APIKey
	user.Password = "******"
	resp["user"] = user
	w.Header().Add("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func main() {

	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	if os.Getenv("GOT_DEBUG") != "" {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}

	config := terraConfig.LoadConfig()
	// Openid
	openidctx = context.Background()
	var googleConfig oauth2.Config
	var googleVerifier *oidc.IDTokenVerifier
	if os.Getenv("GOOGLE_OAUTH2_CLIENT_ID") != "" {
		googleProvider, _ = oidc.NewProvider(openidctx, "https://accounts.google.com")
		oidcConfig := &oidc.Config{
			ClientID: os.Getenv("GOOGLE_OAUTH2_CLIENT_ID"),
		}
		googleVerifier = googleProvider.Verifier(oidcConfig)

		googleConfig = oauth2.Config{
			ClientID:     os.Getenv("GOOGLE_OAUTH2_CLIENT_ID"),
			ClientSecret: os.Getenv("GOOGLE_OAUTH2_CLIENT_SECRET"),
			Endpoint:     googleProvider.Endpoint(),
			RedirectURL:  fmt.Sprintf("%s/app/auth/oidc/google/callback", config.URL),
			Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
		}
	}
	// aaiConfig
	var aaiConfig oauth2.Config
	var aaiVerifier *oidc.IDTokenVerifier
	if os.Getenv("AAI_OAUTH2_CLIENT_ID") != "" {
		var aaiErr error
		aaiProvider, aaiErr = oidc.NewProvider(openidctx, "https://login.elixir-czech.org/oidc/")
		if aaiErr != nil {
			log.Error().Msgf("AAI OIDC error %s", aaiErr)
			os.Exit(1)
		}
		oidcConfig := &oidc.Config{
			ClientID: os.Getenv("AAI_OAUTH2_CLIENT_ID"),
		}
		aaiVerifier = aaiProvider.Verifier(oidcConfig)

		aaiConfig = oauth2.Config{
			ClientID:     os.Getenv("AAI_OAUTH2_CLIENT_ID"),
			ClientSecret: os.Getenv("AAI_OAUTH2_CLIENT_SECRET"),
			Endpoint:     aaiProvider.Endpoint(),
			RedirectURL:  fmt.Sprintf("%s/app/auth/oidc/aai/callback", config.URL),
			Scopes:       []string{oidc.ScopeOpenID, "email"},
		}
	}

	state := "gotauth"

	consulErr := terraConfig.ConsulDeclare("got-auth", "/auth")
	if consulErr != nil {
		log.Error().Msgf("Failed to register: %s", consulErr.Error())
		panic(consulErr)
	}
	mongoClient, err := mongo.NewClient(mongoOptions.Client().ApplyURI(config.Mongo.URL))
	if err != nil {
		log.Printf("[ERROR] Failed to connect to mongo server %s\n", config.Mongo.URL)
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

	r := mux.NewRouter()
	r.HandleFunc("/auth", HomeHandler).Methods("GET")
	r.HandleFunc("/auth/api", APIKeyHandler).Methods("GET")       // Checks API Key
	r.HandleFunc("/auth/token", TokenRenewHandler).Methods("GET") // Renew token
	r.HandleFunc("/auth/login", LoginHandler).Methods("POST")
	r.HandleFunc("/auth/register", RegisterHandler).Methods("POST")
	r.HandleFunc("/auth/me", MeHandler).Methods("GET")
	r.HandleFunc("/auth/user", UsersHandler).Methods("GET")
	r.HandleFunc("/auth/user/{id}", UserHandler).Methods("GET")
	r.HandleFunc("/auth/user/{id}", UserUpdateHandler).Methods("PUT")
	r.HandleFunc("/auth/user/{id}/password", UserPasswordUpdateHandler).Methods("PUT")

	r.HandleFunc("/auth/oidc/google", func(w http.ResponseWriter, r *http.Request) {
		if os.Getenv("GOOGLE_OAUTH2_CLIENT_ID") == "" {
			w.WriteHeader(http.StatusNotFound)
		}
		http.Redirect(w, r, googleConfig.AuthCodeURL(state), http.StatusFound)
	})

	r.HandleFunc("/auth/oidc/google/callback", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("state") != state {
			http.Error(w, "state did not match", http.StatusBadRequest)
			return
		}

		oauth2Token, err := googleConfig.Exchange(openidctx, r.URL.Query().Get("code"))
		if err != nil {
			http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
			return
		}
		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			http.Error(w, "No id_token field in oauth2 token.", http.StatusInternalServerError)
			return
		}
		idToken, err := googleVerifier.Verify(openidctx, rawIDToken)
		if err != nil {
			http.Error(w, "Failed to verify ID Token: "+err.Error(), http.StatusInternalServerError)
			return
		}

		oauth2Token.AccessToken = "****"

		resp := struct {
			OAuth2Token   *oauth2.Token
			IDTokenClaims *json.RawMessage // ID Token payload is just JSON.
		}{oauth2Token, new(json.RawMessage)}

		if err := idToken.Claims(&resp.IDTokenClaims); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		userInfo := make(map[string]string)
		json.Unmarshal(*resp.IDTokenClaims, &userInfo)
		// Check if user exists, if no, create it
		filter := bson.M{"uid": userInfo["email"]}
		loggedUser := terraUser.User{}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		err = userCollection.FindOne(ctx, filter).Decode(&loggedUser)
		if err == mongo.ErrNoDocuments {
			hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(terraUtils.RandStringBytes(20)), bcrypt.DefaultCost)
			loggedUser = terraUser.User{
				UID:      userInfo["email"],
				Password: string(hashedPassword),
				Admin:    false,
				Email:    userInfo["email"],
				Logged:   true,
				APIKey:   terraUtils.RandStringBytes(20),
				Kind:     "google",
			}
			_, err := userCollection.InsertOne(ctx, &loggedUser)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			userCreatedMessage(loggedUser.UID, loggedUser.Kind)
		} else {
			log.Error().Str("user", userInfo["email"]).Msg("User already exists\n")
		}

		loggedUser.Password = ""
		userJSON, _ := json.Marshal(loggedUser)
		token, tokenErr := terraToken.FernetEncode(userJSON)
		if tokenErr != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Header().Add("Content-Type", "application/json")
			respError := map[string]interface{}{"message": "token creation error"}
			json.NewEncoder(w).Encode(respError)
			return
		}

		userToken := make(map[string]string)
		userToken["token"] = string(token)
		userToken["apikey"] = loggedUser.APIKey
		userToken["uid"] = loggedUser.UID
		w.Header().Add("Content-Type", "application/json")
		json.NewEncoder(w).Encode(userToken)

	})

	r.HandleFunc("/auth/oidc/aai", func(w http.ResponseWriter, r *http.Request) {
		if os.Getenv("AAI_OAUTH2_CLIENT_ID") == "" {
			w.WriteHeader(http.StatusNotFound)
		}
		http.Redirect(w, r, aaiConfig.AuthCodeURL(state), http.StatusFound)
	})

	r.HandleFunc("/auth/oidc/aai/callback", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("state") != state {
			http.Error(w, "state did not match", http.StatusBadRequest)
			return
		}

		oauth2Token, err := aaiConfig.Exchange(openidctx, r.URL.Query().Get("code"))
		if err != nil {
			http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
			return
		}
		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			http.Error(w, "No id_token field in oauth2 token.", http.StatusInternalServerError)
			return
		}
		idToken, err := aaiVerifier.Verify(openidctx, rawIDToken)
		if err != nil {
			http.Error(w, "Failed to verify ID Token: "+err.Error(), http.StatusInternalServerError)
			return
		}

		oauth2Token.AccessToken = "****"

		resp := struct {
			OAuth2Token   *oauth2.Token
			IDTokenClaims *json.RawMessage // ID Token payload is just JSON.
		}{oauth2Token, new(json.RawMessage)}

		if err := idToken.Claims(&resp.IDTokenClaims); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		userInfo := make(map[string]string)
		json.Unmarshal(*resp.IDTokenClaims, &userInfo)
		// Check if user exists, if no, create it
		filter := bson.M{"uid": userInfo["sub"]}
		loggedUser := terraUser.User{}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		err = userCollection.FindOne(ctx, filter).Decode(&loggedUser)
		if err == mongo.ErrNoDocuments {
			hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(terraUtils.RandStringBytes(20)), bcrypt.DefaultCost)
			loggedUser = terraUser.User{
				UID:      userInfo["sub"],
				Password: string(hashedPassword),
				Admin:    false,
				Email:    userInfo["email"],
				Logged:   true,
				APIKey:   terraUtils.RandStringBytes(20),
				Kind:     "aai",
			}
			_, err := userCollection.InsertOne(ctx, &loggedUser)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			userCreatedMessage(loggedUser.UID, loggedUser.Kind)
		} else {
			log.Error().Str("user", userInfo["sub"]).Msg("User already exists\n")
		}

		loggedUser.Password = ""
		userJSON, _ := json.Marshal(loggedUser)
		token, tokenErr := terraToken.FernetEncode(userJSON)
		if tokenErr != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Header().Add("Content-Type", "application/json")
			respError := map[string]interface{}{"message": "token creation error"}
			json.NewEncoder(w).Encode(respError)
			return
		}

		userToken := make(map[string]string)
		userToken["token"] = string(token)
		userToken["apikey"] = loggedUser.APIKey
		userToken["uid"] = loggedUser.UID
		w.Header().Add("Content-Type", "application/json")
		json.NewEncoder(w).Encode(userToken)

	})

	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowCredentials: true,
		AllowedHeaders:   []string{"Authorization", "X-API-Key", "Content-Type"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE"},
	})

	handler := c.Handler(r)

	loggedRouter := handlers.LoggingHandler(os.Stdout, handler)

	srv := &http.Server{
		Handler: loggedRouter,
		Addr:    fmt.Sprintf("%s:%d", config.Web.Listen, config.Web.Port),
		// Good practice: enforce timeouts for servers you create!
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	srv.ListenAndServe()

}
