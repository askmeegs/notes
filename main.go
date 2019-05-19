package main

import (
	"cloud.google.com/go/firestore"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/mitchellh/mapstructure"
	"google.golang.org/api/iterator"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/gorilla/mux"
)

var (
	client     *firestore.Client // DB connection, https://cloud.google.com/firestore/
	jwtKey     []byte            //signing key for JWT tokens
	validCreds map[string]string //database of users
)

// JWT Claims
type Claims struct {
	Username string `json:"username"`
	Password string `json:"password"`
	jwt.StandardClaims
}

type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Data model. One note contains text, and created-time.
type Note struct {
	Note      string `json:"note"`
	Timestamp string `json:"timestamp"`
}

// AddNote takes a string, applies a timestamp, and writes to the DB
func HomeHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	io.WriteString(w, `"{"message": "you must log in to continue"}"`)
}

// Login takes a username/password and, if valid creds, returns a JWT cookie
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	var creds Credentials

	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if _, ok := validCreds[creds.Username]; !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	expectedPassword, ok := validCreds[creds.Username]
	if !ok || expectedPassword != creds.Password {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	expirationTime := time.Now().Add(30 * time.Minute)
	claims := &Claims{
		Username: creds.Username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Value:   tokenString,
		Expires: expirationTime,
	})

}

// AddNote takes a string, applies a timestamp, and writes to the DB
func AddNoteHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")

	if err := validateJwt(r); err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, err.Error())
		return
	}

	var note Note
	err := json.NewDecoder(r.Body).Decode(&note)
	if err != nil {
		log.Println(err)
		return
	}

	n := Note{
		Timestamp: time.Now().Format(time.RFC3339),
		Note:      note.Note,
	}

	_, _, err = client.Collection("notes").Add(context.Background(), n)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		io.WriteString(w, err.Error())
	}
	w.WriteHeader(http.StatusCreated)
}

// GetNotesHandler gets all notes
func GetNotesHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	if err := validateJwt(r); err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, err.Error())
		return
	}

	notes, err := getNotesHelper()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		io.WriteString(w, err.Error())
	}

	output, _ := json.Marshal(notes)

	w.WriteHeader(http.StatusOK)
	io.WriteString(w, string(output))
}

// GetRandomNotes returns 1 random note
func GetRandomNoteHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	if err := validateJwt(r); err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, err.Error())
		return
	}

	notes, err := getNotesHelper()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		io.WriteString(w, err.Error())
	}

	rand.Seed(time.Now().Unix())
	note := notes[rand.Intn(len(notes))]

	output, _ := json.Marshal(note)
	w.WriteHeader(http.StatusOK)
	io.WriteString(w, string(output))
}

func main() {
	var wait time.Duration
	flag.DurationVar(&wait, "graceful-timeout", time.Second*15, "graceful timeout")
	flag.Parse()

	// process env
	signkey := os.Getenv("SIGNKEY")
	if signkey == "" {
		log.Fatal("need JWT sign key")
	}
	jwtKey = []byte(signkey)

	username := os.Getenv("USERNAME")
	if username == "" {
		log.Fatal("need username")
	}
	password := os.Getenv("PASSWORD")
	if username == "" {
		log.Fatal("need password")
	}
	validCreds = map[string]string{username: password}

	r := mux.NewRouter()

	// Add your routes as needed
	r.HandleFunc("/", HomeHandler)
	r.HandleFunc("/login", LoginHandler).Methods("POST", "OPTIONS")
	r.HandleFunc("/notes", AddNoteHandler).Methods("POST", "OPTIONS")
	r.HandleFunc("/notes", GetNotesHandler).Methods("GET")
	r.HandleFunc("/notes/random", GetRandomNoteHandler).Methods("GET")

	srv := &http.Server{
		Addr:         "0.0.0.0:8080",
		WriteTimeout: time.Second * 15,
		ReadTimeout:  time.Second * 15,
		IdleTimeout:  time.Second * 60,
		Handler:      r, // Pass our instance of gorilla/mux in.
	}

	log.Println("📝 NOTES SERVER STARTING....")
	ctx := context.Background()
	var err error
	client, err = firestore.NewClient(ctx, "notesdb")
	if err != nil {
		log.Fatalf("Failed to create firestore client: %v", err)
	}
	defer client.Close()

	//start server
	go func() {
		if err := srv.ListenAndServe(); err != nil {
			log.Println(err)
		}
	}()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	// Block until signal
	<-c

	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	srv.Shutdown(ctx)
	log.Println("shutting down")
	os.Exit(0)
}

// HELPERS
func getNotesHelper() ([]Note, error) {
	ctx := context.Background()
	notes := []Note{}
	iter := client.Collection("notes").Documents(ctx)
	for {
		doc, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return notes, err
		}
		var n Note
		mapstructure.Decode(doc.Data(), &n)
		notes = append(notes, n)
	}
	return notes, nil
}

// JWT
func validateJwt(r *http.Request) error {
	// accept both Authorization: Bearer and Cookies
	reqToken := r.Header.Get("Authorization")
	splitToken := strings.Split(reqToken, "Bearer")
	tknStr := ""
	if len(splitToken) >= 2 {
		tknStr = strings.TrimSpace(splitToken[1])
	} else { // try cookie
		c, err := r.Cookie("token")
		if err != nil {
			return err
		}
		tknStr = c.Value
	}
	claims := &Claims{}

	// verify signature
	tkn, err := jwt.ParseWithClaims(tknStr, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	if err != nil {
		return fmt.Errorf("err on Parse With Claims: %v", err)
	}
	if !tkn.Valid {
		return fmt.Errorf("invalid token")
	}

	// verify claims
	if _, ok := validCreds[claims.Username]; !ok {
		return fmt.Errorf("invalid username")
	}
	return nil
}
