package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"os"
)

type Credentials struct {
	Cid     string `json:"cid"`
	Csecret string `json:"cs"`
}

type User struct {
	Sub           string `json:"sub"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Profile       string `json:"profile"`
	Picture       string `json:"picture"`
	Email         string `json:"email"`
	EmailVerified string `json:"email_verified"`
	Gender        string `json:"gender"`
}

var cred Credentials
var conf *oauth2.Config
var state string
var store = sessions.NewCookieStore([]byte("something-very-secret"))

func randToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

func init() {
	store.Options = &sessions.Options{
		Domain:   "127.0.0.1",
		Path:     "/",
		MaxAge:   3600 * 8, // 8 hours
		HttpOnly: true,
	}

	gob.Register(&User{})
	file, err := ioutil.ReadFile("./creds.json")
	if err != nil {
		fmt.Printf("File Error: %v\n", err)
		os.Exit(1)
	}

	json.Unmarshal(file, &cred)

	conf = &oauth2.Config{
		ClientID:     cred.Cid,
		ClientSecret: cred.Csecret,
		RedirectURL:  "http://127.0.0.1:8888/auth",
		Scopes: []string{
			// scopes allow you to selectively choose the permissions you need access to
			// for simple login you can just use userinfo.email
			"https://www.googleapis.com/auth/userinfo.email",
		},
		Endpoint: google.Endpoint,
	}
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	templ := template.Must(template.ParseFiles("./templates/index.html"))
	templ.Execute(w, nil)
}

func getLoginURL(state string) string {
	return conf.AuthCodeURL(state)
}

func httpError(w http.ResponseWriter, err error, reason string) {
	fmt.Println(reason)
	http.Error(w, err.Error(), http.StatusInternalServerError)
	return
}

func authHandler(w http.ResponseWriter, r *http.Request) {
	store, err := store.Get(r, "session")
	if err != nil {
		httpError(w, err, "Getting store")
		return
	}
	query := r.URL.Query()
	retrievedState := store.Values["state"]
	if retrievedState != query.Get("state") {
		httpError(w, err, "Getting state from store")
		return
	}

	token, err := conf.Exchange(context.Background(), query.Get("code"))
	if err != nil {
		httpError(w, err, "token bit")
		return
	}
	client := conf.Client(context.Background(), token)
	email, err := client.Get("https://www.googleapis.com/oauth2/v3/userinfo")
	if err != nil {
		httpError(w, err, "email bit")
		return
	}
	defer email.Body.Close()
	data, _ := ioutil.ReadAll(email.Body)
	user := User{}
	json.Unmarshal(data, &user)
	store.Values["user"] = user
	store.Save(r, w)
	fmt.Println("Email body: ", string(data))
	http.Redirect(w, r, "/user", 301)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	state = randToken()
	store, err := store.Get(r, "session")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	store.Values["state"] = state
	store.Save(r, w)

	loginUrl := struct{ Url string }{}
	loginUrl.Url = getLoginURL(state)
	templ := template.Must(template.ParseFiles("./templates/login.html"))
	templ.Execute(w, loginUrl)
}

func userHandler(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "session")
	if err != nil {
		httpError(w, err, "getting session")
		return
	}

	val := session.Values["user"]
	fmt.Println(val)
	var user = &User{}
	if _, ok := val.(*User); !ok {
		httpError(w, err, "getting user from session ")
		return
	}
	user = val.(*User)
	templ := template.Must(template.ParseFiles("./templates/user.html"))
	templ.Execute(w, user)
}

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/", indexHandler)
	r.HandleFunc("/login", loginHandler)
	r.HandleFunc("/auth", authHandler)
	r.HandleFunc("/user", userHandler)
	http.Handle("/", r)
	srv := &http.Server{
		Handler: r,
		Addr:    "127.0.0.1:8888",
	}

	log.Fatal(srv.ListenAndServe())
}
