package main

import (
	"database/sql"
	"fmt"
	"html/template"
	"log"
	"net/http"

	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB
var tmpl *template.Template

func init() {
	// Kết nối MySQL
	var err error
	db, err = sql.Open("mysql", "root:Minhhieu11012004@tcp(localhost:3306)/user")
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}

	// Kiểm tra kết nối
	err = db.Ping()
	if err != nil {
		log.Fatal("Database not reachable:", err)
	}

	// Tải các file HTML template
	tmpl = template.Must(template.ParseGlob("templates/*.html"))
}

func main() {
	http.HandleFunc("/", loginForm)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/register", registerForm)
	http.HandleFunc("/registerSubmit", registerHandler)
	log.Println("Server started at http://localhost:8080")
	http.ListenAndServe(":8080", nil)
}

// Hiển thị form đăng nhập
func loginForm(w http.ResponseWriter, r *http.Request) {
	tmpl.ExecuteTemplate(w, "login.html", nil)
}

// Xử lý đăng nhập
func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	var hashedPassword string
	err := db.QueryRow("SELECT password FROM users WHERE username = ?", username).Scan(&hashedPassword)
	if err != nil {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	// So sánh mật khẩu
	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err != nil {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	fmt.Fprintf(w, "Login successful! Welcome, %s!", username)
}

// Hiển thị form đăng ký
func registerForm(w http.ResponseWriter, r *http.Request) {
	tmpl.ExecuteTemplate(w, "register.html", nil)
}

// Xử lý đăng ký
func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/register", http.StatusSeeOther)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	// Kiểm tra nếu username đã tồn tại
	var existingUser string
	err := db.QueryRow("SELECT username FROM users WHERE username = ?", username).Scan(&existingUser)
	if err == nil {
		http.Error(w, "Username already exists", http.StatusConflict)
		return
	}

	// Hash mật khẩu
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}

	// Lưu thông tin người dùng vào cơ sở dữ liệu
	_, err = db.Exec("INSERT INTO users (username, password) VALUES (?, ?)", username, hashedPassword)
	if err != nil {
		http.Error(w, "Failed to register user", http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(w, "Registration successful! Welcome, %s!", username)
}
