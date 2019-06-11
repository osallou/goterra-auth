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
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/rs/cors"
	"go.mongodb.org/mongo-driver/bson"
	mongo "go.mongodb.org/mongo-driver/mongo"
	mongoOptions "go.mongodb.org/mongo-driver/mongo/options"

	terraUtils "github.com/osallou/goterra-auth/lib/utils"
	terraConfig "github.com/osallou/goterra-lib/lib/config"
	terraToken "github.com/osallou/goterra-lib/lib/token"
	terraUser "github.com/osallou/goterra-lib/lib/user"

	oidc "github.com/coreos/go-oidc"
	// "golang.org/x/net/context"
)

// Openid
var openidctx context.Context
var provider *oidc.Provider

// Version of server
var Version string

var mongoClient mongo.Client
var userCollection *mongo.Collection

// CheckTokenForDeployment checks JWT token
func CheckTokenForDeployment(authToken string) (user terraUser.User, err error) {
	// config := terraConfig.LoadConfig()

	user = terraUser.User{}
	err = nil

	tokenStr := strings.Replace(authToken, "Bearer", "", -1)
	tokenStr = strings.TrimSpace(tokenStr)

	msg, msgErr := terraToken.FernetDecode([]byte(tokenStr))
	if msgErr != nil {
		fmt.Printf("failed to decode token\n")
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

// AuthData is result struct for authentication with user data and an authentication token
type AuthData struct {
	User  terraUser.User
	Token string
}

// APIKeyHandler checks user api key and returns user info
var APIKeyHandler = func(w http.ResponseWriter, r *http.Request) {
	// config := terraConfig.LoadConfig()
	apiKey := r.Header.Get("X-API-KEY")
	if apiKey == "" {
		w.WriteHeader(http.StatusForbidden)
		w.Header().Add("Content-Type", "application/json")
		respError := map[string]interface{}{"message": "invalid data"}
		json.NewEncoder(w).Encode(respError)
		return
	}
	/*
		data := &APIData{}
		err := json.NewDecoder(r.Body).Decode(data)
		if err != nil {
			w.WriteHeader(http.StatusForbidden)
			w.Header().Add("Content-Type", "application/json")
			respError := map[string]interface{}{"message": "invalid data"}
			json.NewEncoder(w).Encode(respError)
			return
		}
	*/

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
	// Openid
	openidctx = context.Background()
	var googleConfig oauth2.Config
	var verifier *oidc.IDTokenVerifier
	if os.Getenv("GOOGLE_OAUTH2_CLIENT_ID") != "" {
		provider, _ = oidc.NewProvider(openidctx, "https://accounts.google.com")
		oidcConfig := &oidc.Config{
			ClientID: os.Getenv("GOOGLE_OAUTH2_CLIENT_ID"),
		}
		verifier = provider.Verifier(oidcConfig)

		googleConfig = oauth2.Config{
			ClientID:     os.Getenv("GOOGLE_OAUTH2_CLIENT_ID"),
			ClientSecret: os.Getenv("GOOGLE_OAUTH2_CLIENT_SECRET"),
			Endpoint:     provider.Endpoint(),
			RedirectURL:  fmt.Sprintf("%s/app/auth/oidc/google/callback", config.URL),
			Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
		}
	}
	state := "gotauth"

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
	r.HandleFunc("/auth/api", APIKeyHandler).Methods("GET") // Checks API Key
	r.HandleFunc("/auth/login", LoginHandler).Methods("POST")
	r.HandleFunc("/auth/register", RegisterHandler).Methods("POST")
	r.HandleFunc("/auth/me", MeHandler).Methods("GET")

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
		idToken, err := verifier.Verify(openidctx, rawIDToken)
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
			loggedUser = terraUser.User{
				UID:      userInfo["email"],
				Password: terraUtils.RandStringBytes(20),
				Admin:    false,
				Email:    userInfo["email"],
				Logged:   true,
				APIKey:   terraUtils.RandStringBytes(20),
			}
			_, err := userCollection.InsertOne(ctx, &loggedUser)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		} else {
			fmt.Printf("User already exists\n")
		}

		mySigningKey := []byte(config.Secret)

		expirationTime := time.Now().Add(24 * time.Hour)
		claims := &Claims{
			UID:   loggedUser.UID,
			Email: loggedUser.Email,
			// Namespaces: user.Namespaces,
			StandardClaims: jwt.StandardClaims{
				ExpiresAt: expirationTime.Unix(),
				Audience:  "goterra/auth",
			},
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, _ := token.SignedString(mySigningKey)

		userToken := make(map[string]string)
		userToken["token"] = tokenString
		userToken["apikey"] = loggedUser.APIKey
		w.Header().Add("Content-Type", "application/json")
		json.NewEncoder(w).Encode(userToken)

	})

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
