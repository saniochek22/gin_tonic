package main

import (
    "crypto/rand"
    "encoding/base64"
    "html/template"
    "log"
    "net/http"
    "path/filepath"

    "github.com/jinzhu/gorm"
    _ "github.com/lib/pq"
    "golang.org/x/crypto/bcrypt"
)

var (
    templates *template.Template
    db        *gorm.DB
)

// User модель для пользователей
type User struct {
    ID        uint   `gorm:"primary_key"`
    Username  string `gorm:"unique;not null"`
    Password  string `gorm:"not null"`
    SessionID string
}

func init() {
    var err error
    // Подключаемся к базе данных
    connStr := "host=localhost port=5432 user=postgres password=admin dbname=myapp sslmode=disable"
    db, err = gorm.Open("postgres", connStr)
    if err != nil {
        log.Fatal("Failed to connect to database:", err)
    }

    // Автоматически мигрируем модели
    db.AutoMigrate(&User{})

    // Парсим все шаблоны вместе
    templates = template.Must(template.ParseFiles(
        filepath.Join("templates", "menu.html"),
        filepath.Join("templates", "index.html"),
        filepath.Join("templates", "about.html"),
        filepath.Join("templates", "login.html"),
        filepath.Join("templates", "register.html"),
    ))
}

func renderTemplate(w http.ResponseWriter, tmpl string, data interface{}) {
    if err := templates.ExecuteTemplate(w, tmpl, data); err != nil {
        http.Error(w, "Error rendering template: "+err.Error(), http.StatusInternalServerError)
    }
}

func generateSessionID() (string, error) {
    b := make([]byte, 32)
    _, err := rand.Read(b)
    if err != nil {
        return "", err
    }
    return base64.URLEncoding.EncodeToString(b), nil
}

func isAuthenticated(r *http.Request) bool {
    cookie, err := r.Cookie("session_id")
    if err != nil || cookie == nil {
        return false
    }
    var user User
    if err := db.Where("session_id = ?", cookie.Value).First(&user).Error; err != nil {
        return false
    }
    return true
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method == http.MethodPost {
        username := r.FormValue("username")
        password := r.FormValue("password")
        confirmPassword := r.FormValue("confirm_password")

        if password != confirmPassword {
            renderTemplate(w, "register.html", map[string]interface{}{
                "Error": "Passwords do not match",
            })
            return
        }

        hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
        if err != nil {
            http.Error(w, "Error hashing password: "+err.Error(), http.StatusInternalServerError)
            return
        }

        user := User{Username: username, Password: string(hashedPassword)}
        if err := db.Create(&user).Error; err != nil {
            renderTemplate(w, "register.html", map[string]interface{}{
                "Error": "Username already exists",
            })
            return
        }
        renderTemplate(w, "register.html", map[string]interface{}{
            "Success": "Registration successful. You can now log in.",
        })
        return
    }
    renderTemplate(w, "register.html", nil)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method == http.MethodPost {
        username := r.FormValue("username")
        password := r.FormValue("password")

        var user User
        if err := db.Where("username = ?", username).First(&user).Error; err != nil || !checkPasswordHash(password, user.Password) {
            renderTemplate(w, "login.html", map[string]interface{}{
                "Error": "Invalid username or password",
            })
            return
        }

        sessionID, err := generateSessionID()
        if err != nil {
            http.Error(w, "Error generating session ID: "+err.Error(), http.StatusInternalServerError)
            return
        }

        user.SessionID = sessionID
        db.Save(&user)

        http.SetCookie(w, &http.Cookie{
            Name:  "session_id",
            Value: sessionID,
            Path:  "/",
        })
        http.Redirect(w, r, "/", http.StatusSeeOther)
        return
    }
    renderTemplate(w, "login.html", nil)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
    http.SetCookie(w, &http.Cookie{
        Name:   "session_id",
        Value:  "",
        Path:   "/",
        MaxAge: -1,
    })
    http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func protectedHandler(w http.ResponseWriter, r *http.Request) {
    if !isAuthenticated(r) {
        http.Redirect(w, r, "/login", http.StatusSeeOther)
        return
    }
    renderTemplate(w, "index.html", nil)
}

func main() {
    fs := http.FileServer(http.Dir("static"))
    http.Handle("/static/", http.StripPrefix("/static/", fs))

    http.HandleFunc("/register", registerHandler)
    http.HandleFunc("/login", loginHandler)
    http.HandleFunc("/logout", logoutHandler)

    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        if r.URL.Path == "/" || r.URL.Path == "/index.html" {
            protectedHandler(w, r)
            return
        }
        http.NotFound(w, r)
    })

    http.HandleFunc("/about", func(w http.ResponseWriter, r *http.Request) {
        if isAuthenticated(r) {
            renderTemplate(w, "about.html", nil)
            return
        }
        http.Redirect(w, r, "/login", http.StatusSeeOther)
    })

    log.Println("Server is running on http://localhost:8080")
    if err := http.ListenAndServe(":8080", nil); err != nil {
        log.Fatal("Error starting server:", err)
    }
}

func checkPasswordHash(password, hash string) bool {
    err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
    return err == nil
}
