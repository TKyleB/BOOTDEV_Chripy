package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	internal "github.com/TKyleB/BOOTDEV_Chripy/internal/auth"
	"github.com/TKyleB/BOOTDEV_Chripy/internal/database"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

type apiConfig struct {
	fileserverHits  atomic.Int32
	dbQueries       *database.Queries
	platform        string
	secret          string
	tokenExpiration time.Duration
	polkaKey        string
}

type User struct {
	ID          uuid.UUID `json:"id"`
	CreatedAt   time.Time `json:"created_at:"`
	UpdatedAt   time.Time `json:"updated_at"`
	Email       string    `json:"email"`
	IsChirpyRed bool      `json:"is_chirpy_red"`
}
type Chirp struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at:"`
	UpdatedAt time.Time `json:"updated_at"`
	Body      string    `json:"body"`
	UserID    uuid.UUID `json:"user_id"`
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	}
}
func (cfg *apiConfig) handleMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	serverHitsCount := cfg.fileserverHits.Load()
	metricsText := fmt.Sprintf(
		`<html>
		<body>
		  <h1>Welcome, Chirpy Admin</h1>
		  <p>Chirpy has been visited %d times!</p>
		</body>
	  </html>`, serverHitsCount)
	w.Write([]byte(metricsText))
}
func (cfg *apiConfig) resetMetrics(w http.ResponseWriter, r *http.Request) {
	if cfg.platform != "dev" {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	err := cfg.dbQueries.DeleteUsers(r.Context())
	if err != nil {
		log.Printf("Error %v", err)
	}
	log.Printf("TRIED TO DELETE")
	cfg.fileserverHits.Store(0)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func main() {
	// Initial Setup
	godotenv.Load()
	dbURL := os.Getenv("DB_URL")
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Printf("Error opening connecting to database: %s", err)
	}

	mux := http.NewServeMux()
	port := "8080"
	server := http.Server{
		Handler: mux,
		Addr:    ":" + port,
	}
	apiConfig := apiConfig{
		dbQueries:       database.New(db),
		platform:        os.Getenv("PLATFORM"),
		secret:          os.Getenv("SECRET"),
		tokenExpiration: time.Hour,
		polkaKey:        os.Getenv("POLKA_KEY"),
	}

	// Routes
	mux.Handle("/app/", apiConfig.middlewareMetricsInc(http.StripPrefix("/app", http.FileServer(http.Dir(".")))))
	mux.HandleFunc("GET /api/healthz/", handleHealthz)
	mux.HandleFunc("GET /api/chirps/{chirpID}", apiConfig.handleGetChirp)
	mux.HandleFunc("GET /api/chirps/", apiConfig.handleGetChirps)
	mux.HandleFunc("POST /api/chirps", apiConfig.handleChirps)
	mux.HandleFunc("DELETE /api/chirps/{chirpID}", apiConfig.handleDeleteChirp)

	mux.HandleFunc("POST /api/login", apiConfig.handleLogin)
	mux.HandleFunc("POST /api/users", apiConfig.handleUsers)
	mux.HandleFunc("POST /api/refresh", apiConfig.handleRefresh)
	mux.HandleFunc("POST /api/revoke", apiConfig.handleRevoke)
	mux.HandleFunc("PUT /api/users", apiConfig.handleUsersUpdate)

	mux.HandleFunc("POST /api/polka/webhooks", apiConfig.handlePolka)

	mux.HandleFunc("GET /admin/metrics/", apiConfig.handleMetrics)
	mux.HandleFunc("POST /admin/reset", apiConfig.resetMetrics)
	server.ListenAndServe()
}

func handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}
func (cfg *apiConfig) handleGetChirp(w http.ResponseWriter, r *http.Request) {
	chirpID, err := uuid.Parse(r.PathValue("chirpID"))
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Unable to parse chirpID")
		return
	}
	chirp, err := cfg.dbQueries.GetChirp(r.Context(), chirpID)
	if err != nil {
		respondWithError(w, http.StatusNotFound, "Chirp  not found")
		return
	}
	respondWithJSON(w, http.StatusOK, Chirp{ID: chirp.ID, CreatedAt: chirp.CreatedAt, UpdatedAt: chirp.UpdatedAt, Body: chirp.Body, UserID: chirp.UserID})
}
func (cfg *apiConfig) handleGetChirps(w http.ResponseWriter, r *http.Request) {
	qAuthor := r.URL.Query().Get("author_id")
	qSort := r.URL.Query().Get("sort")
	var dbChirps []database.Chirp
	var err error
	if qAuthor == "" {
		dbChirps, err = cfg.dbQueries.GetChirps(r.Context())
		if err != nil {
			log.Printf("Error getting chirps: %v", err)
			respondWithError(w, http.StatusBadRequest, "")
			return
		}
	} else {
		authorID, _ := uuid.Parse(qAuthor)
		dbChirps, err = cfg.dbQueries.GetChirpByAuthor(r.Context(), authorID)
		if err != nil {
			respondWithError(w, http.StatusNotFound, "Author Not Found")
			return
		}
	}

	var chirps []Chirp
	for _, chirp := range dbChirps {
		chirps = append(chirps, Chirp{ID: chirp.ID, CreatedAt: chirp.CreatedAt, UpdatedAt: chirp.UpdatedAt, Body: chirp.Body, UserID: chirp.UserID})
	}
	if qSort == "desc" {
		slices.Reverse(chirps)
	}
	respondWithJSON(w, http.StatusOK, chirps)

}
func (cfg *apiConfig) handleDeleteChirp(w http.ResponseWriter, r *http.Request) {
	parsedToken, err := internal.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Invalid Token")
		return
	}
	tokenUserID, err := internal.ValidateJWT(parsedToken, cfg.secret)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Invalid Token")
		return
	}

	parsedchirpID := r.PathValue("chirpID")
	chirpID, err := uuid.Parse(parsedchirpID)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid Chirp ID")
		return
	}
	chirp, err := cfg.dbQueries.GetChirp(r.Context(), chirpID)
	if err != nil {
		respondWithError(w, http.StatusNotFound, "Chirp not found")
		return
	}

	if chirp.UserID != tokenUserID {
		respondWithError(w, http.StatusForbidden, "Forbidden")
		return
	}

	err = cfg.dbQueries.DeleteChirp(r.Context(), chirpID)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "DB ERROR")
		return
	}
	respondWithJSON(w, http.StatusNoContent, "")

}
func (cfg *apiConfig) handleChirps(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Body string `json:"body"`
	}
	token, err := internal.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "auth token not provided")
		return
	}
	userID, err := internal.ValidateJWT(token, cfg.secret)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "invalid token")
		return
	}

	chirpWordFilter := map[string]bool{
		"kerfuffle": true,
		"sharbert":  true,
		"fornax":    true,
	}
	defer r.Body.Close()
	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err = decoder.Decode(&params)
	if err != nil {
		log.Printf("Error decoding JSON: %v", err)
		respondWithError(w, http.StatusBadRequest, "")
		return
	}
	user, err := cfg.dbQueries.GetUser(r.Context(), userID)
	if err != nil {
		log.Printf("User not found. %v", err)
		respondWithError(w, http.StatusBadRequest, "")
		return
	}

	// Check Chirp Length
	if len(params.Body) > 140 {
		respondWithError(w, http.StatusBadRequest, "Chirp is too long")
		return
	}

	cleanedChirp := CleanChirp(params.Body, chirpWordFilter)
	chirp, err := cfg.dbQueries.CreateChirp(r.Context(), database.CreateChirpParams{Body: cleanedChirp, UserID: user.ID})
	if err != nil {
		log.Printf("Error creating chirp: %v", err)
	}
	respondWithJSON(w, http.StatusCreated, Chirp{ID: chirp.ID, CreatedAt: chirp.CreatedAt, UpdatedAt: chirp.UpdatedAt, Body: chirp.Body, UserID: chirp.UserID})

}
func (cfg *apiConfig) handleLogin(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	defer r.Body.Close()
	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	if err := decoder.Decode(&params); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid Request")
		return
	}
	user, _ := cfg.dbQueries.GetUserByEmail(r.Context(), params.Email)
	err := internal.CheckPasswordHash(params.Password, user.HashedPassword)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Incorrect email or password")
		return
	}

	token, err := internal.MakeJWT(user.ID, cfg.secret, time.Duration(cfg.tokenExpiration))
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Error creating token")
		return
	}
	refreshTokenString, err := internal.MakeRefreshToken()
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Error creating refresh token")
		return
	}
	refreshToken, err := cfg.dbQueries.CreateRefreshToken(r.Context(), database.CreateRefreshTokenParams{Token: refreshTokenString, UserID: user.ID, ExpiresAt: time.Now().AddDate(0, 0, 60), RevokedAt: sql.NullTime{}})
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Error adding refresh token to DB")
		return
	}

	type AuthResponse struct {
		ID           uuid.UUID `json:"id"`
		CreatedAt    time.Time `json:"created_at"`
		UpdatedAt    time.Time `json:"updated_at"`
		Email        string    `json:"email"`
		Token        string    `json:"token"`
		IsChirpyRED  bool      `json:"is_chirpy_red"`
		RefreshToken string    `json:"refresh_token"`
	}
	respondWithJSON(w, http.StatusOK, AuthResponse{ID: user.ID, CreatedAt: user.CreatedAt, UpdatedAt: user.UpdatedAt, Email: user.Email, Token: token, RefreshToken: refreshToken.Token, IsChirpyRED: user.IsChirpyRed.Bool})

}
func (cfg *apiConfig) handleRefresh(w http.ResponseWriter, r *http.Request) {
	// Parse headers for refresh token string
	refreshTokenString, err := internal.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid Headers")
		return
	}
	// Check if token is in the database
	refreshToken, err := cfg.dbQueries.GetRefreshToken(r.Context(), refreshTokenString)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Invalid Token")
		return
	}

	// Generate new JWT Token
	newToken, err := internal.MakeJWT(refreshToken.UserID, cfg.secret, cfg.tokenExpiration)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Error creating JWT")
		return
	}

	respondWithJSON(w, http.StatusOK, struct {
		Token string `json:"token"`
	}{Token: newToken})

}
func (cfg *apiConfig) handleRevoke(w http.ResponseWriter, r *http.Request) {
	// Parse headers for refresh token string
	refreshTokenString, err := internal.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid Headers")
		return
	}

	// Update and revoke token
	cfg.dbQueries.RevokeToken(r.Context(), refreshTokenString)
	respondWithJSON(w, http.StatusNoContent, "Token Revoked")

}
func (cfg *apiConfig) handleUsersUpdate(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	parsedToken, err := internal.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Invalid Token")
		return
	}
	userID, err := internal.ValidateJWT(parsedToken, cfg.secret)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Invalid Token")
		return
	}
	parser := json.NewDecoder(r.Body)
	params := parameters{}
	err = parser.Decode(&params)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	defer r.Body.Close()
	hashed_password, err := internal.HashPassword(params.Password)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid password format")
		return
	}
	updatedUser, err := cfg.dbQueries.UpdateUser(r.Context(), database.UpdateUserParams{ID: userID, HashedPassword: hashed_password, Email: params.Email})
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Databse Error")
		return
	}
	respondWithJSON(w, http.StatusOK, User{ID: updatedUser.ID, CreatedAt: updatedUser.CreatedAt, UpdatedAt: updatedUser.UpdatedAt, Email: updatedUser.Email})

}
func (cfg *apiConfig) handlePolka(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Event string            `json:"event"`
		Data  map[string]string `json:"data"`
	}
	key, err := internal.GetAPIKey(r.Header)
	if err != nil || key != cfg.polkaKey {
		respondWithError(w, http.StatusUnauthorized, "")
	}
	params := parameters{}
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&params); err != nil {
		respondWithError(w, http.StatusBadRequest, "invalid request")
		return
	}
	if params.Event != "user.upgraded" {
		respondWithError(w, http.StatusNoContent, "")
		return
	}
	parsedUserID, _ := uuid.Parse(params.Data["user_id"])
	user, err := cfg.dbQueries.GetUser(r.Context(), parsedUserID)
	if err != nil {
		respondWithError(w, http.StatusNotFound, "User not found")
		return
	}
	_, err = cfg.dbQueries.UpgradeToChirpyRed(r.Context(), user.ID)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "DB Error")
		return
	}
	respondWithJSON(w, http.StatusNoContent, "")
}

func (cfg *apiConfig) handleUsers(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		log.Printf("Error decoding request into JSON: %s", err)
		return
	}
	hashedPassword, err := internal.HashPassword(params.Password)
	if err != nil {
		log.Printf("Error hashing password %v", err)
		respondWithError(w, http.StatusBadRequest, "")
		return
	}
	user, err := cfg.dbQueries.CreateUser(r.Context(), database.CreateUserParams{Email: params.Email, HashedPassword: hashedPassword})
	if err != nil {
		log.Printf("Error creating user: %v", err)
		return
	}
	respondWithJSON(w, http.StatusCreated, User{ID: user.ID, CreatedAt: user.CreatedAt, UpdatedAt: user.UpdatedAt, Email: user.Email, IsChirpyRed: user.IsChirpyRed.Bool})

}
func respondWithError(w http.ResponseWriter, code int, msg string) {
	response := ErrorResponse{Error: msg}
	data, err := json.Marshal(response)
	if err != nil {
		log.Printf("Error marshaling error response %s", err)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(data)
}
func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	dat, err := json.Marshal(payload)
	if err != nil {
		log.Printf("Error Marshaling JSON data. %s", err)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(dat)
}

type ErrorResponse struct {
	Error string `json:"error"`
}
type SuccessResponse struct {
	Valid bool `json:"valid"`
}

func CleanChirp(chirp string, wordFilter map[string]bool) string {
	words := strings.Split(chirp, " ")
	for i, word := range words {
		if wordFilter[strings.ToLower(word)] {
			words[i] = "****"
		}
	}
	return strings.Join(words, " ")
}
