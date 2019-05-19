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
	client     *firestore.Client
	err        error
	jwtKey     []byte
	validCreds map[string]string
)

type Claims struct {
	Username string `json:"username"`
	Password string `json:"password"`
	jwt.StandardClaims
}

type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

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

	// User must exist
	if _, ok := validCreds[creds.Username]; !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Get the expected password from our in memory map
	expectedPassword, ok := validCreds[creds.Username]
	if !ok || expectedPassword != creds.Password {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	expirationTime := time.Now().Add(5 * time.Minute)
	claims := &Claims{
		Username: creds.Username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	// Declare the token with the algorithm used for signing, and the claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	// Create the JWT string
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	fmt.Printf("🔒 user %s logged in\n", creds.Username)
	// Finally, we set the client cookie for "token" as the JWT we just generated
	// we also set an expiry time which is the same as the token itself
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

// GetRandomNotes returns 1 random note via query
// TODO - avoid fetching all notes first
func GetRandomNoteHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	if err := validateJwt(r); err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, err.Error())
		return
	}

	// actually do stuff
	notes, err := getNotesHelper()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		io.WriteString(w, err.Error())
	}

	rand.Seed(time.Now().Unix()) // initialize global pseudo random generator
	note := notes[rand.Intn(len(notes))]

	output, _ := json.Marshal(note)
	w.WriteHeader(http.StatusOK)
	io.WriteString(w, string(output))
}

func main() {
	var wait time.Duration
	flag.DurationVar(&wait, "graceful-timeout", time.Second*15, "the duration for which the server gracefully wait for existing connections to finish - e.g. 15s or 1m")
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
	fmt.Printf("%#v", validCreds)

	r := mux.NewRouter()

	// Add your routes as needed
	r.HandleFunc("/", HomeHandler)
	r.HandleFunc("/login", LoginHandler).Methods("POST", "OPTIONS")
	r.HandleFunc("/notes", AddNoteHandler).Methods("POST", "OPTIONS")
	r.HandleFunc("/notes", GetNotesHandler).Methods("GET")
	r.HandleFunc("/notes/random", GetRandomNoteHandler).Methods("GET")

	srv := &http.Server{
		Addr: "0.0.0.0:8080",
		// Good practice to set timeouts to avoid Slowloris attacks.
		WriteTimeout: time.Second * 15,
		ReadTimeout:  time.Second * 15,
		IdleTimeout:  time.Second * 60,
		Handler:      r, // Pass our instance of gorilla/mux in.
	}

	log.Println("📝 NOTES SERVER STARTING....")
	ctx := context.Background()
	client, err = firestore.NewClient(ctx, "notesdb") //TODO - make notesdb a flag
	if err != nil {
		log.Fatalf("Failed to create firestore client: %v", err)
	}
	defer client.Close()

	// Run our server in a goroutine so that it doesn't block.
	go func() {
		if err := srv.ListenAndServe(); err != nil {
			log.Println(err)
		}
	}()

	c := make(chan os.Signal, 1)
	// We'll accept graceful shutdowns when quit via SIGINT (Ctrl+C)
	// SIGKILL, SIGQUIT or SIGTERM (Ctrl+/) will not be caught.
	signal.Notify(c, os.Interrupt)

	// Block until we receive our signal.
	<-c

	// Create a deadline to wait for.
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	// Doesn't block if no connections, but will otherwise wait
	// until the timeout deadline.
	srv.Shutdown(ctx)
	// Optionally, you could run srv.Shutdown in a goroutine and block on
	// <-ctx.Done() if your application should wait for other services
	// to finalize based on context cancellation.
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

	fmt.Printf("validing JWT with claims: %#v\n", claims)

	// verify claims
	if _, ok := validCreds[claims.Username]; !ok {
		return fmt.Errorf("invalid username")
	}

	return nil
}
