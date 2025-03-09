package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// Modèles de données
type User struct {
	gorm.Model
	Email        string `gorm:"uniqueIndex"`
	PasswordHash string
	FirstName    string
	LastName     string
	Role         string
}

type AuthSession struct {
	gorm.Model
	UserID       uint
	SessionToken string `gorm:"uniqueIndex"`
	ExpiresAt    time.Time
	ClientID     string
	RedirectURI  string
}

type Client struct {
	gorm.Model
	ClientID     string `gorm:"uniqueIndex"`
	ClientName   string
	RedirectURIs string // Séparées par des virgules
	Secret       string
}

// Configuration globale
var (
	db           *gorm.DB
	jwtSecret    []byte
	cookieSecret []byte
)

// Initialisation de la base de données
func initDB() {
	var err error
	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		os.Getenv("DB_HOST"),
		os.Getenv("DB_PORT"),
		os.Getenv("DB_USER"),
		os.Getenv("DB_PASSWORD"),
		os.Getenv("DB_NAME"))

	db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatalf("Échec de connexion à la base de données: %v", err)
	}

	// Migration des schémas
	db.AutoMigrate(&User{}, &AuthSession{}, &Client{})

	// Créer un client de test si nécessaire
	var clientCount int64
	db.Model(&Client{}).Count(&clientCount)
	if clientCount == 0 {
		// Créer des clients par défaut pour appA et appB
		appAClient := Client{
			ClientID:     "app_a_client",
			ClientName:   "Application A",
			RedirectURIs: "http://localhost:3000/callback,http://localhost:3000/auth/callback",
			Secret:       generateRandomString(32),
		}

		appBClient := Client{
			ClientID:     "app_b_client",
			ClientName:   "Application B",
			RedirectURIs: "http://localhost:3001/callback,http://localhost:3001/auth/callback",
			Secret:       generateRandomString(32),
		}

		db.Create(&appAClient)
		db.Create(&appBClient)

		log.Printf("Clients par défaut créés. Secret pour appA: %s, Secret pour appB: %s",
			appAClient.Secret, appBClient.Secret)
	}
}

// Génération d'une chaîne aléatoire
func generateRandomString(length int) string {
	b := make([]byte, length)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

func main() {
	// Charger les variables d'environnement
	if err := godotenv.Load(); err != nil {
		log.Println("Aucun fichier .env trouvé")
	}

	// Configuration
	jwtSecret = []byte(os.Getenv("JWT_SECRET"))
	if len(jwtSecret) == 0 {
		jwtSecret = []byte(generateRandomString(32))
		log.Printf("JWT_SECRET non défini, généré aléatoirement: %s", string(jwtSecret))
	}

	cookieSecret = []byte(os.Getenv("COOKIE_SECRET"))
	if len(cookieSecret) == 0 {
		cookieSecret = []byte(generateRandomString(32))
		log.Printf("COOKIE_SECRET non défini, généré aléatoirement: %s", string(cookieSecret))
	}

	// Initialiser la base de données
	initDB()

	// Configurer Gin
	router := gin.Default()

	// Templates HTML
	log.Println("Starting to load HTML templates...")
	router.LoadHTMLGlob("templates/*")
	log.Println("HTML templates loaded (hopefully without errors)")

	// Fichiers statiques
	router.Static("/static", "./static")

	// Middleware pour les sessions
	store := cookie.NewStore(cookieSecret)
	store.Options(sessions.Options{
		Path:     "/",
		MaxAge:   3600 * 24, // 24 heures
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteNoneMode, // Important pour le SSO cross-domain
	})
	router.Use(sessions.Sessions("auth_session", store))

	// Configuration CORS
	router.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	// Middleware CSRF
	router.Use(CSRFMiddleware())

	// Routes d'authentification
	auth := router.Group("/auth")
	{
		auth.GET("/login", showLoginPage)
		auth.POST("/login", loginHandler)
		auth.GET("/logout", logoutHandler)
		auth.GET("/authorize", authorizeHandler)
		auth.GET("/register", showRegisterPage)
		auth.POST("/register", registerHandler)
	}

	// API pour les applications mobiles et services
	api := router.Group("/api")
	{
		api.POST("/token", tokenHandler)
		api.POST("/refresh", refreshTokenHandler)
		api.GET("/validate", validateTokenHandler)
		api.POST("/register", apiRegisterHandler)
	}

	// Route par défaut
	router.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "home.html", gin.H{
			"title": "Service d'authentification",
		})
	})

	// Démarrer le serveur
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Serveur démarré sur le port %s", port)
	// {{- /*
	// router.RunTLS(":"+port, "/etc/ssl/certs/cert.pem", "/etc/ssl/certs/key.pem")
	// */}}
	router.Run(":" + port)
}

// Middleware CSRF
func CSRFMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Ignorer pour les requêtes GET, HEAD, OPTIONS
		if c.Request.Method == "GET" || c.Request.Method == "HEAD" || c.Request.Method == "OPTIONS" {
			c.Next()
			return
		}

		session := sessions.Default(c)
		csrfToken := session.Get("csrf_token")

		// Vérifier si le token CSRF existe dans la session
		if csrfToken == nil {
			c.JSON(http.StatusForbidden, gin.H{"error": "CSRF token manquant"})
			c.Abort()
			return
		}

		// Vérifier le token dans l'en-tête ou le formulaire
		requestToken := c.Request.Header.Get("X-CSRF-Token")
		if requestToken == "" {
			requestToken = c.PostForm("csrf_token")
		}

		if requestToken == "" || requestToken != csrfToken.(string) {
			c.JSON(http.StatusForbidden, gin.H{"error": "CSRF token invalide"})
			c.Abort()
			return
		}

		c.Next()
	}
}

// Handlers pour les pages web
func showLoginPage(c *gin.Context) {
	log.Println("showLoginPage handler called")
	log.Println("Before c.HTML in showLoginPage")
	c.HTML(http.StatusOK, "login.html", gin.H{
		"title": "Connexion TEST", // Modified title for testing
	})
	log.Println("After c.HTML in showLoginPage")
}

func loginHandler(c *gin.Context) {
	email := c.PostForm("email")
	password := c.PostForm("password")
	clientID := c.PostForm("client_id")
	redirectURI := c.PostForm("redirect_uri")

	// Vérifier les identifiants
	var user User
	result := db.Where("email = ?", email).First(&user)
	if result.Error != nil || !checkPasswordHash(password, user.PasswordHash) {
		c.HTML(http.StatusUnauthorized, "login.html", gin.H{
			"title":        "Connexion",
			"error":        "Email ou mot de passe incorrect",
			"client_id":    clientID,
			"redirect_uri": redirectURI,
		})
		return
	}

	// Créer une session
	session := sessions.Default(c)
	session.Set("user_id", user.ID)
	session.Save()

	// Logger la connexion
	log.Printf("Utilisateur %s connecté avec succès", email)

	// Rediriger vers la page d'autorisation
	c.Redirect(http.StatusFound, fmt.Sprintf("/auth/authorize?client_id=%s&redirect_uri=%s", clientID, redirectURI))
}

func authorizeHandler(c *gin.Context) {
	// Vérifier l'authentification
	session := sessions.Default(c)
	userID := session.Get("user_id")
	if userID == nil {
		c.Redirect(http.StatusFound, fmt.Sprintf("/auth/login?client_id=%s&redirect_uri=%s",
			c.Query("client_id"), c.Query("redirect_uri")))
		return
	}

	clientID := c.Query("client_id")
	redirectURI := c.Query("redirect_uri")

	// Vérifier le client et l'URI de redirection
	var client Client
	result := db.Where("client_id = ?", clientID).First(&client)
	if result.Error != nil {
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"error": "Client non reconnu",
		})
		return
	}

	// Générer un code d'autorisation
	authCode := generateRandomString(32)

	// Stocker le code d'autorisation
	authSession := AuthSession{
		UserID:       userID.(uint),
		SessionToken: authCode,
		ExpiresAt:    time.Now().Add(10 * time.Minute),
		ClientID:     clientID,
		RedirectURI:  redirectURI,
	}
	db.Create(&authSession)

	// Redirection vers l'application cliente avec le code
	redirectURL := fmt.Sprintf("%s?code=%s", redirectURI, authCode)
	c.Redirect(http.StatusFound, redirectURL)
}

func logoutHandler(c *gin.Context) {
	session := sessions.Default(c)
	session.Clear()
	session.Save()
	c.Redirect(http.StatusFound, "/")
}

func showRegisterPage(c *gin.Context) {
	// Générer et stocker un token CSRF
	session := sessions.Default(c)
	csrfToken := generateRandomString(32)
	session.Set("csrf_token", csrfToken)
	session.Save()

	c.HTML(http.StatusOK, "register.html", gin.H{
		"title":      "Inscription",
		"csrf_token": csrfToken,
	})
}

func registerHandler(c *gin.Context) {
	email := c.PostForm("email")
	password := c.PostForm("password")
	firstName := c.PostForm("first_name")
	lastName := c.PostForm("last_name")

	// Vérifier si l'utilisateur existe déjà
	var existingUser User
	result := db.Where("email = ?", email).First(&existingUser)
	if result.Error == nil {
		c.HTML(http.StatusBadRequest, "register.html", gin.H{
			"title": "Inscription",
			"error": "Cet email est déjà utilisé",
		})
		return
	}

	// Hasher le mot de passe
	hashedPassword, err := hashPassword(password)
	if err != nil {
		c.HTML(http.StatusInternalServerError, "register.html", gin.H{
			"title": "Inscription",
			"error": "Erreur lors de l'inscription",
		})
		return
	}

	// Créer le nouvel utilisateur
	user := User{
		Email:        email,
		PasswordHash: hashedPassword,
		FirstName:    firstName,
		LastName:     lastName,
		Role:         "user",
	}

	db.Create(&user)

	// Logger l'inscription
	log.Printf("Nouvel utilisateur inscrit: %s", email)

	c.Redirect(http.StatusFound, "/auth/login")
}

// Handlers pour l'API
func tokenHandler(c *gin.Context) {
	code := c.PostForm("code")
	clientID := c.PostForm("client_id")
	clientSecret := c.PostForm("client_secret")

	// Vérifier le client
	var client Client
	result := db.Where("client_id = ? AND secret = ?", clientID, clientSecret).First(&client)
	if result.Error != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Client non reconnu"})
		return
	}

	// Vérifier le code d'autorisation
	var authSession AuthSession
	result = db.Where("session_token = ? AND client_id = ? AND expires_at > ?",
		code, clientID, time.Now()).First(&authSession)

	if result.Error != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Code d'autorisation invalide ou expiré"})
		return
	}

	// Récupérer l'utilisateur
	var user User
	db.First(&user, authSession.UserID)

	// Générer des tokens JWT
	accessToken, refreshToken, err := generateTokens(user, clientID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Erreur lors de la génération des tokens"})
		return
	}

	// Supprimer le code d'autorisation utilisé
	db.Delete(&authSession)

	c.JSON(http.StatusOK, gin.H{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"token_type":    "Bearer",
		"expires_in":    3600,
		"user": gin.H{
			"id":         user.ID,
			"email":      user.Email,
			"first_name": user.FirstName,
			"last_name":  user.LastName,
		},
	})
}

func refreshTokenHandler(c *gin.Context) {
	refreshToken := c.PostForm("refresh_token")
	clientID := c.PostForm("client_id")
	clientSecret := c.PostForm("client_secret")

	// Vérifier le client
	var client Client
	result := db.Where("client_id = ? AND secret = ?", clientID, clientSecret).First(&client)
	if result.Error != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Client non reconnu"})
		return
	}

	// Vérifier et parser le refresh token
	token, err := jwt.Parse(refreshToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("méthode de signature non valide: %v", token.Header["alg"])
		}
		return jwtSecret, nil
	})

	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Refresh token invalide"})
		return
	}

	// Extraire les claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Impossible de lire les claims"})
		return
	}

	// Vérifier que c'est bien un refresh token et pour le bon client
	if claims["type"] != "refresh" || claims["client_id"] != clientID {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Token invalide pour ce client"})
		return
	}

	// Récupérer l'utilisateur
	var user User
	userID := uint(claims["user_id"].(float64))
	db.First(&user, userID)

	// Générer de nouveaux tokens
	newAccessToken, newRefreshToken, err := generateTokens(user, clientID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Erreur lors de la génération des tokens"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token":  newAccessToken,
		"refresh_token": newRefreshToken,
		"token_type":    "Bearer",
		"expires_in":    3600,
	})
}

func validateTokenHandler(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" || len(authHeader) < 8 || authHeader[:7] != "Bearer " {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Token manquant ou format invalide"})
		return
	}

	tokenString := authHeader[7:]

	// Vérifier et parser le token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("méthode de signature non valide: %v", token.Header["alg"])
		}
		return jwtSecret, nil
	})

	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Token invalide"})
		return
	}

	// Extraire les claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Impossible de lire les claims"})
		return
	}

	// Vérifier que c'est un access token
	if claims["type"] != "access" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Type de token invalide"})
		return
	}

	// Récupérer l'utilisateur
	var user User
	userID := uint(claims["user_id"].(float64))
	db.First(&user, userID)

	c.JSON(http.StatusOK, gin.H{
		"valid": true,
		"user": gin.H{
			"id":         user.ID,
			"email":      user.Email,
			"first_name": user.FirstName,
			"last_name":  user.LastName,
		},
	})
}

func apiRegisterHandler(c *gin.Context) {
	var userData struct {
		Email     string `json:"email" binding:"required"`
		Password  string `json:"password" binding:"required"`
		FirstName string `json:"first_name"`
		LastName  string `json:"last_name"`
	}

	if err := c.ShouldBindJSON(&userData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Vérifier si l'utilisateur existe déjà
	var existingUser User
	result := db.Where("email = ?", userData.Email).First(&existingUser)
	if result.Error == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Cet email est déjà utilisé"})
		return
	}

	// Hasher le mot de passe
	hashedPassword, err := hashPassword(userData.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Erreur lors de l'inscription"})
		return
	}

	// Créer le nouvel utilisateur
	user := User{
		Email:        userData.Email,
		PasswordHash: hashedPassword,
		FirstName:    userData.FirstName,
		LastName:     userData.LastName,
		Role:         "user",
	}

	db.Create(&user)

	// Logger l'inscription
	log.Printf("Nouvel utilisateur inscrit via API: %s", userData.Email)

	c.JSON(http.StatusCreated, gin.H{
		"success": true,
		"user": gin.H{
			"id":         user.ID,
			"email":      user.Email,
			"first_name": user.FirstName,
			"last_name":  user.LastName,
		},
	})
}

// Fonctions utilitaires
func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func generateTokens(user User, clientID string) (string, string, error) {
	// Générer un access token
	accessTokenClaims := jwt.MapClaims{
		"user_id":   user.ID,
		"email":     user.Email,
		"role":      user.Role,
		"client_id": clientID,
		"type":      "access",
		"exp":       time.Now().Add(time.Hour).Unix(),
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessTokenClaims)
	accessTokenString, err := accessToken.SignedString(jwtSecret)
	if err != nil {
		return "", "", err
	}

	// Générer un refresh token
	refreshTokenClaims := jwt.MapClaims{
		"user_id":   user.ID,
		"client_id": clientID,
		"type":      "refresh",
		"exp":       time.Now().Add(30 * 24 * time.Hour).Unix(), // 30 jours
	}

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshTokenClaims)
	refreshTokenString, err := refreshToken.SignedString(jwtSecret)
	if err != nil {
		return "", "", err
	}

	return accessTokenString, refreshTokenString, nil
}
