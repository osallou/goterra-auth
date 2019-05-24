package main

/*
 TODO auth user against ldap, openid, ...
*/

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"golang.org/x/crypto/bcrypt"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/rs/cors"
	"go.mongodb.org/mongo-driver/bson"
	mongo "go.mongodb.org/mongo-driver/mongo"
	mongoOptions "go.mongodb.org/mongo-driver/mongo/options"

	terraConfig "github.com/osallou/goterra-auth/lib/config"
	terraUser "github.com/osallou/goterra-auth/lib/user"
)

// Version of server
var Version string

var mongoClient mongo.Client
var userCollection *mongo.Collection

func setupResponse(w *http.ResponseWriter, req *http.Request) {
	(*w).Header().Set("Access-Control-Allow-Origin", "*")
	(*w).Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	(*w).Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-API-Key, Authorization")
}

// HomeHandler manages base entrypoint
var HomeHandler = func(w http.ResponseWriter, r *http.Request) {
	resp := map[string]interface{}{"version": Version, "message": "ok"}
	w.Header().Add("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// Claims contains JWT claims
type Claims struct {
	UID    string   `json:"uid"`
	Email  string   `json:"email"`
	Groups []string `json:"groups"`
	jwt.StandardClaims
}

// LoginData contains user credentials
type LoginData struct {
	UID      string `json:"uid"`
	Password string `json:"password"`
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
		UID:    "anonymous",
		Email:  "anonymous@do-no-reply.fake",
		Groups: make([]string, 0),
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
			Audience:  "goterra/auth",
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString(mySigningKey)

	resp := map[string]interface{}{"token": tokenString}
	w.Header().Add("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func main() {

	config := terraConfig.LoadConfig()
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
	r.HandleFunc("/auth/login", LoginHandler).Methods("POST")

	handler := cors.Default().Handler(r)

	srv := &http.Server{
		Handler: handler,
		Addr:    fmt.Sprintf("%s:%d", config.Web.Listen, config.Web.Port),
		// Good practice: enforce timeouts for servers you create!
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	log.Fatal(srv.ListenAndServe())

}
