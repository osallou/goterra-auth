package main

/*
 TODO auth user against ldap, openid, ...
*/

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/rs/cors"
	"go.mongodb.org/mongo-driver/bson"
	mongo "go.mongodb.org/mongo-driver/mongo"
	mongoOptions "go.mongodb.org/mongo-driver/mongo/options"

	terraUtils "github.com/osallou/goterra-auth/lib/utils"
	terraConfig "github.com/osallou/goterra-lib/lib/config"
	terraUser "github.com/osallou/goterra-lib/lib/user"
)

// Version of server
var Version string

var mongoClient mongo.Client
var userCollection *mongo.Collection

// CheckTokenForDeployment checks JWT token
func CheckTokenForDeployment(authToken string) (user terraUser.User, err error) {
	config := terraConfig.LoadConfig()

	user = terraUser.User{}
	err = nil

	tokenStr := strings.Replace(authToken, "Bearer", "", -1)
	tokenStr = strings.TrimSpace(tokenStr)
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(config.Secret), nil
	})
	if err != nil || !token.Valid || claims.Audience != "goterra/auth" {
		fmt.Printf("Token error: %v\n", err)
		return user, errors.New("invalid token")
	}

	user.UID = claims.UID
	user.Email = claims.Email
	// user.Namespaces = claims.Namespaces
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
	user, err := CheckTokenForDeployment(r.Header.Get("Authorization"))
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		w.Header().Add("Content-Type", "application/json")
		respError := map[string]interface{}{"message": "invalid token"}
		json.NewEncoder(w).Encode(respError)
		return
	}
	filter := bson.M{"uid": user.UID}
	loggedUser := terraUser.User{}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err = userCollection.FindOne(ctx, filter).Decode(&loggedUser)

	if err != nil || !loggedUser.Admin {
		w.WriteHeader(http.StatusForbidden)
		w.Header().Add("Content-Type", "application/json")
		respError := map[string]interface{}{"message": "not authorized"}
		json.NewEncoder(w).Encode(respError)
		return
	}

	data := &terraUser.User{}
	data.APIKey = terraUtils.RandStringBytes(20)
	err = json.NewDecoder(r.Body).Decode(data)

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

// APIKeyHandler checks user api key and returns user info
var APIKeyHandler = func(w http.ResponseWriter, r *http.Request) {
	// config := terraConfig.LoadConfig()
	data := &APIData{}
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
	filter := bson.M{"apikey": data.Key}
	err = userCollection.FindOne(ctx, filter).Decode(&user)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		w.Header().Add("Content-Type", "application/json")
		respError := map[string]interface{}{"message": "user not found"}
		json.NewEncoder(w).Encode(respError)
		return
	}
	w.Header().Add("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}

// LoginHandler manages authentication
var LoginHandler = func(w http.ResponseWriter, r *http.Request) {
	config := terraConfig.LoadConfig()
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

	mySigningKey := []byte(config.Secret)

	expirationTime := time.Now().Add(1 * time.Hour)
	claims := &Claims{
		UID:   user.UID,
		Email: user.Email,
		// Namespaces: user.Namespaces,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
			Audience:  "goterra/auth",
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString(mySigningKey)

	//resp := map[string]interface{}({"token": tokenstring})
	resp := make(map[string]string)
	resp["token"] = tokenString
	resp["apikey"] = user.APIKey
	w.Header().Add("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func main() {
	config := terraConfig.LoadConfig()
	consulErr := terraConfig.ConsulDeclare("got-auth", "/auth")
	if consulErr != nil {
		fmt.Printf("Failed to register: %s", consulErr.Error())
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
	r.HandleFunc("/auth/api", APIKeyHandler).Methods("POST") // Checks API Key
	r.HandleFunc("/auth/login", LoginHandler).Methods("POST")
	r.HandleFunc("/auth/register", RegisterHandler).Methods("POST")

	handler := cors.Default().Handler(r)

	loggedRouter := handlers.LoggingHandler(os.Stdout, handler)

	srv := &http.Server{
		Handler: loggedRouter,
		Addr:    fmt.Sprintf("%s:%d", config.Web.Listen, config.Web.Port),
		// Good practice: enforce timeouts for servers you create!
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	log.Fatal(srv.ListenAndServe())

}
