package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"html/template"
	"net/http"

	_ "github.com/go-sql-driver/mysql"
)

var db *sql.DB
var sessions = map[string]string{}

func main() {
	var err error
	db, err = sql.Open("mysql", "root:Kanha#1234@tcp(127.0.0.1:3306)/proj1")
	if err != nil {
		panic(err)
	}

	if err = db.Ping(); err != nil {
		panic(err)
	}
	fmt.Println("Connected to MySQL")
	http.HandleFunc("/", serveSignupPage)
	http.HandleFunc("/signup", signupHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/dashbord", dashbordHandler)
	http.HandleFunc("/update", updateHandler)
	http.HandleFunc("/delete", deleteHandler)
	http.HandleFunc("/logout", logoutHandler)

	fmt.Println("Server running at http://localhost:8000")
	http.ListenAndServe(":8000", nil)
}

func serveSignupPage(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFiles("templates/signup.html"))
	tmpl.Execute(w, nil)
}

func signupHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		tmpl := template.Must(template.ParseFiles("templates/signup.html"))
		tmpl.Execute(w, nil)
		return
	}
	r.ParseForm()
	username := r.FormValue("username")
	password := r.FormValue("password")
	confirm := r.FormValue("confirm")
	if password != confirm {
		renderError(w, "Passwords do not match")
		return
	}
	var exists string
	err := db.QueryRow("SELECT username FROM users WHERE username = ?", username).Scan(&exists)
	if err != sql.ErrNoRows && err != nil {
		renderError(w, "Database error: "+err.Error())
		return
	}
	if exists != "" {
		renderError(w, "Username already taken")
		return
	}
	_, err = db.Exec("INSERT INTO users (username, password) VALUES (?, ?)", username, password)
	if err != nil {
		renderError(w, "Error creating user")
		return
	}
	fmt.Println("Registered:", username)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		tmpl := template.Must(template.ParseFiles("templates/login.html"))
		tmpl.Execute(w, nil)
		return
	}
	r.ParseForm()
	username := r.FormValue("username")
	password := r.FormValue("password")
	var dbPassword string
	err := db.QueryRow("SELECT password FROM users WHERE username = ?", username).Scan(&dbPassword)
	if err != nil || dbPassword != password {
		renderError(w, "Invalid username or password")
		return
	}
	sessionID, _ := generateSessionID()
	sessions[sessionID] = username
	http.SetCookie(w, &http.Cookie{
		Name:  "session",
		Value: sessionID,
		Path:  "/",
	})
	http.Redirect(w, r, "/dashbord", http.StatusSeeOther)
}

func dashbordHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session")
	if err != nil || sessions[cookie.Value] == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	username := sessions[cookie.Value]
	fmt.Printf("%s accessed dashbord\n", username)
	tmpl := template.Must(template.ParseFiles("templates/dashbord.html"))
	tmpl.Execute(w, struct{ Username string }{Username: username})
}
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session")
	if err == nil {
		delete(sessions, cookie.Value)
		http.SetCookie(w, &http.Cookie{
			Name:   "session",
			Value:  "",
			Path:   "/",
			MaxAge: -1,
		})
	}
	fmt.Println("User logout form Dashbord")
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func renderError(w http.ResponseWriter, msg string) {
	tmpl := template.Must(template.ParseFiles("templates/error.html"))
	tmpl.Execute(w, struct{ Message string }{Message: msg})
}

func updateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		tmpl := template.Must(template.ParseFiles("templates/update.html"))
		tmpl.Execute(w, nil)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Invalid method", http.StatusMethodNotAllowed)
		return
	}

	err := r.ParseForm()
	if err != nil {
		http.Error(w, "Parsing Error", http.StatusBadRequest)
		return
	}

	currentUsername := r.FormValue("username")
	oldPassword := r.FormValue("old_password")
	newUsername := r.FormValue("new_username")
	newPassword := r.FormValue("new_password")

	// Step 1: Check if username + old password match
	var dbPassword string
	err = db.QueryRow("SELECT password FROM users WHERE username = ?", currentUsername).Scan(&dbPassword)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	if dbPassword != oldPassword {
		http.Error(w, "Old password is incorrect", http.StatusUnauthorized)
		return
	}

	// Step 2: Update username and password
	stmt, err := db.Prepare("UPDATE users SET username = ?, password = ? WHERE username = ?")
	if err != nil {
		http.Error(w, "Database prepare error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer stmt.Close()

	_, err = stmt.Exec(newUsername, newPassword, currentUsername)
	if err != nil {
		http.Error(w, "Database execution error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	fmt.Printf("username = %s to Update \nnew username = %s \n ", currentUsername, newUsername)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func deleteHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		tmpl := template.Must(template.ParseFiles("templates/delete.html"))
		tmpl.Execute(w, nil)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Invalid method", http.StatusMethodNotAllowed)
		return
	}

	err := r.ParseForm()
	if err != nil {
		http.Error(w, "Parsing Error", http.StatusBadRequest)
		return
	}

	password := r.FormValue("password")
	username := r.FormValue("username")

	fmt.Printf("Deleting user > Username: %s, Password: %s\n", username, password)

	stmt, err := db.Prepare("DELETE FROM users WHERE password = ?")
	if err != nil {
		http.Error(w, "Database prepare error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer stmt.Close()

	result, err := stmt.Exec(password)
	if err != nil {
		http.Error(w, "Database execution error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		http.Error(w, "No user found with given credentials", http.StatusNotFound)
		return
	}

	http.Redirect(w, r, "/signup", http.StatusSeeOther)
}

func generateSessionID() (string, error) {
	bytes := make([]byte, 16)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
