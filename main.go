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
	client *firestore.Client
	err    error
	// jwtKey
	// actualU
)

var jwtKey = []byte("nycbagel")
var actualU = "argonaut"

type Claims struct {
	Uuid string `json:"uuid"`
	jwt.StandardClaims
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
	io.WriteString(w, `"{"message": "this is the notes server"}"`)
}

// AddNote takes a string, applies a timestamp, and writes to the DB
func AddNoteHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")

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

	r := mux.NewRouter()

	// Add your routes as needed
	r.HandleFunc("/", HomeHandler)
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

	reqToken := r.Header.Get("Authorization")
	splitToken := strings.Split(reqToken, "Bearer")
	if len(splitToken) < 2 {
		return fmt.Errorf("could not parse token")
	}
	tknStr := splitToken[1]

	fmt.Println(tknStr)
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
	if claims.Uuid != actualU {
		return fmt.Errorf("invalid uuid")
	}
	fmt.Println("valid JWT")
	return nil
}
