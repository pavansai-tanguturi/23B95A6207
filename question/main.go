package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const remoteLogURL = "http://20.244.56.144/evaluation-service/logs"
const fixedLogID = "73e1b67a-0867-4d21-a944-610526724400"

type SimpleLog struct {
	LogID   string `json:"logID"`
	Message string `json:"message"`
}

type DetailedLog struct {
	LogID   string `json:"logID"`
	Stack   string `json:"stack"`
	Level   string `json:"level"`
	Package string `json:"package"`
	Message string `json:"message"`
}

func sendSimpleLog(message string) {
	log := SimpleLog{
		LogID:   fixedLogID,
		Message: message,
	}
	data, _ := json.Marshal(log)
	http.Post(remoteLogURL, "application/json", bytes.NewBuffer(data))
}

func sendDetailedLog(stack, level, pkg, message string) {
	log := DetailedLog{
		LogID:   fixedLogID,
		Stack:   stack,
		Level:   level,
		Package: pkg,
		Message: message,
	}
	data, _ := json.Marshal(log)
	http.Post(remoteLogURL, "application/json", bytes.NewBuffer(data))
}

func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		msg := fmt.Sprintf("%s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
		sendSimpleLog(msg)
		next.ServeHTTP(w, r)
	})
}

type URLRecord struct {
	ID        string    `json:"id"`
	URL       string    `json:"url"`
	Shortcode string    `json:"shortcode"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Clicks    int       `json:"clicks"`
}
type Analytics struct {
	Clicks        int       `json:"clicks"`
	LastAccessed  time.Time `json:"last_accessed"`
	CreatedAt     time.Time `json:"created_at"`
	TotalClicks   int       `json:"total_clicks"`
}
type CreateURLRequest struct {
	URL       string `json:"url"`
	Validity  *int   `json:"validity,omitempty"`
	Shortcode string `json:"shortcode,omitempty"`
}
type CreateURLResponse struct {
	ShortLink string `json:"shortlink"`
	Expiry    string `json:"expiry"`
}
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
	Code    int    `json:"code"`
}

type URLShortenerService struct {
	storage  map[string]*URLRecord
	mutex    sync.RWMutex
	hostname string
	port     string
}

func NewURLShortenerService(hostname, port string) *URLShortenerService {
	return &URLShortenerService{
		storage:  make(map[string]*URLRecord),
		hostname: hostname,
		port:     port,
	}
}

func (s *URLShortenerService) generateShortcode() string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	const length = 6

	b := make([]byte, length)
	for i := range b {
		randomBytes := make([]byte, 1)
		rand.Read(randomBytes)
		b[i] = charset[randomBytes[0]%byte(len(charset))]
	}
	return string(b)
}
func (s *URLShortenerService) isValidURL(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	return u.Scheme != "" && u.Host != ""
}
func (s *URLShortenerService) isValidShortcode(shortcode string) bool {
	if len(shortcode) < 1 || len(shortcode) > 20 {
		return false
	}
	for _, char := range shortcode {
		if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9')) {
			return false
		}
	}
	return true
}
func (s *URLShortenerService) sendErrorResponse(w http.ResponseWriter, statusCode int, errorMsg, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	errorResp := ErrorResponse{
		Error:   errorMsg,
		Message: message,
		Code:    statusCode,
	}

	json.NewEncoder(w).Encode(errorResp)

	sendDetailedLog("backend", "error", "handler", fmt.Sprintf("%s: %s", errorMsg, message))
}
func (s *URLShortenerService) CreateShortURL(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.sendErrorResponse(w, http.StatusMethodNotAllowed, "method_not_allowed", "Only POST method is allowed")
		return
	}

	var req CreateURLRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendErrorResponse(w, http.StatusBadRequest, "invalid_json", "Invalid JSON in request body")
		return
	}
	if req.URL == "" {
		s.sendErrorResponse(w, http.StatusBadRequest, "missing_url", "URL is required")
		return
	}

	if !s.isValidURL(req.URL) {
		s.sendErrorResponse(w, http.StatusBadRequest, "invalid_url", "Invalid URL format")
		return
	}
	validity := 30
	if req.Validity != nil {
		validity = *req.Validity
	}

	if validity <= 0 {
		s.sendErrorResponse(w, http.StatusBadRequest, "invalid_validity", "Validity must be a positive integer")
		return
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()
	shortcode := req.Shortcode
	if shortcode != "" {
		if !s.isValidShortcode(shortcode) {
			s.sendErrorResponse(w, http.StatusBadRequest, "invalid_shortcode", "Shortcode must be alphanumeric and between 1-20 characters")
			return
		}
		if _, exists := s.storage[shortcode]; exists {
			s.sendErrorResponse(w, http.StatusConflict, "shortcode_collision", "Shortcode already exists")
			return
		}
	} else {
		for {
			shortcode = s.generateShortcode()
			if _, exists := s.storage[shortcode]; !exists {
				break
			}
		}
	}
	now := time.Now()
	expiresAt := now.Add(time.Duration(validity) * time.Minute)

	record := &URLRecord{
		ID:        shortcode,
		URL:       req.URL,
		Shortcode: shortcode,
		CreatedAt: now,
		ExpiresAt: expiresAt,
		Clicks:    0,
	}

	s.storage[shortcode] = record
	baseURL := fmt.Sprintf("http://%s:%s", s.hostname, s.port)
	shortLink := fmt.Sprintf("%s/%s", baseURL, shortcode)

	response := CreateURLResponse{
		ShortLink: shortLink,
		Expiry:    expiresAt.Format("2006-01-02T15:04:05Z"),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)

	sendSimpleLog(fmt.Sprintf("Short URL created: %s -> %s", req.URL, shortLink))
}
func (s *URLShortenerService) RedirectToURL(w http.ResponseWriter, r *http.Request) {
	shortcode := strings.TrimPrefix(r.URL.Path, "/")

	if r.Method != http.MethodGet {
		s.sendErrorResponse(w, http.StatusMethodNotAllowed, "method_not_allowed", "Only GET method is allowed")
		return
	}

	if shortcode == "" {
		s.sendErrorResponse(w, http.StatusBadRequest, "missing_shortcode", "Shortcode is required")
		return
	}

	s.mutex.Lock()
	record, exists := s.storage[shortcode]
	if !exists {
		s.mutex.Unlock()
		s.sendErrorResponse(w, http.StatusNotFound, "shortcode_not_found", "Shortcode does not exist")
		return
	}
	if time.Now().After(record.ExpiresAt) {
		s.mutex.Unlock()
		s.sendErrorResponse(w, http.StatusGone, "expired_link", "Short link has expired")
		return
	}
	record.Clicks++
	s.mutex.Unlock()

	http.Redirect(w, r, record.URL, http.StatusFound)

	sendSimpleLog(fmt.Sprintf("Redirected: %s -> %s", shortcode, record.URL))
}
func (s *URLShortenerService) GetURLInfo(w http.ResponseWriter, r *http.Request) {
	shortcode := strings.TrimPrefix(r.URL.Path, "/shorturls/")

	if r.Method != http.MethodGet {
		s.sendErrorResponse(w, http.StatusMethodNotAllowed, "method_not_allowed", "Only GET method is allowed")
		return
	}

	if shortcode == "" {
		s.sendErrorResponse(w, http.StatusBadRequest, "missing_shortcode", "Shortcode is required")
		return
	}

	s.mutex.RLock()
	record, exists := s.storage[shortcode]
	s.mutex.RUnlock()

	if !exists {
		s.sendErrorResponse(w, http.StatusNotFound, "shortcode_not_found", "Shortcode does not exist")
		return
	}
	if time.Now().After(record.ExpiresAt) {
		s.sendErrorResponse(w, http.StatusGone, "expired_link", "Short link has expired")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(record)

	sendSimpleLog(fmt.Sprintf("URL info retrieved: %s", shortcode))
}
func (s *URLShortenerService) DeleteShortURL(w http.ResponseWriter, r *http.Request) {
	shortcode := strings.TrimPrefix(r.URL.Path, "/shorturls/")

	if r.Method != http.MethodDelete {
		s.sendErrorResponse(w, http.StatusMethodNotAllowed, "method_not_allowed", "Only DELETE method is allowed")
		return
	}

	if shortcode == "" {
		s.sendErrorResponse(w, http.StatusBadRequest, "missing_shortcode", "Shortcode is required")
		return
	}

	s.mutex.Lock()
	_, exists := s.storage[shortcode]
	if !exists {
		s.mutex.Unlock()
		s.sendErrorResponse(w, http.StatusNotFound, "shortcode_not_found", "Shortcode does not exist")
		return
	}

	delete(s.storage, shortcode)
	s.mutex.Unlock()

	w.WriteHeader(http.StatusNoContent)

	sendSimpleLog(fmt.Sprintf("Short URL deleted: %s", shortcode))
}
func (s *URLShortenerService) GetAnalytics(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	shortcode := ""
	parts := strings.Split(path, "/")
	if len(parts) >= 3 && parts[1] == "shorturls" && len(parts) >= 4 && parts[3] == "analytics" {
		shortcode = parts[2]
	}

	if r.Method != http.MethodGet {
		s.sendErrorResponse(w, http.StatusMethodNotAllowed, "method_not_allowed", "Only GET method is allowed")
		return
	}

	if shortcode == "" {
		s.sendErrorResponse(w, http.StatusBadRequest, "missing_shortcode", "Shortcode is required")
		return
	}

	s.mutex.RLock()
	record, exists := s.storage[shortcode]
	s.mutex.RUnlock()

	if !exists {
		s.sendErrorResponse(w, http.StatusNotFound, "shortcode_not_found", "Shortcode does not exist")
		return
	}

	analytics := Analytics{
		Clicks:       record.Clicks,
		LastAccessed: time.Now(),
		CreatedAt:    record.CreatedAt,
		TotalClicks:  record.Clicks,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(analytics)

	sendSimpleLog(fmt.Sprintf("Analytics retrieved: %s", shortcode))
}

func (s *URLShortenerService) ListAllURLs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.sendErrorResponse(w, http.StatusMethodNotAllowed, "method_not_allowed", "Only GET method is allowed")
		return
	}

	s.mutex.RLock()
	defer s.mutex.RUnlock()
	urls := make([]*URLRecord, 0, len(s.storage))
	now := time.Now()
	activeCount := 0
	expiredCount := 0
	for _, record := range s.storage {
		if now.After(record.ExpiresAt) {
			expiredCount++
		} else {
			activeCount++
			urls = append(urls, record)
		}
	}
	response := map[string]interface{}{
		"urls":          urls,
		"total_count":   len(urls),
		"active_count":  activeCount,
		"expired_count": expiredCount,
		"retrieved_at":  now.Format("2006-01-02T15:04:05Z"),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)

	sendSimpleLog(fmt.Sprintf("Listed all URLs: active=%d, expired=%d", activeCount, expiredCount))
}
func (s *URLShortenerService) setupRoutes() {
	http.HandleFunc("/shorturls", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			s.CreateShortURL(w, r)
		case http.MethodGet:
			s.ListAllURLs(w, r)
		default:
			s.sendErrorResponse(w, http.StatusMethodNotAllowed, "method_not_allowed", "Only GET and POST methods are allowed")
		}
	})

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if strings.Contains(path, "/analytics") {
			s.GetAnalytics(w, r)
			return
		}
		if strings.HasPrefix(path, "/shorturls/") && path != "/shorturls/" {
			switch r.Method {
			case http.MethodGet:
				s.GetURLInfo(w, r)
			case http.MethodDelete:
				s.DeleteShortURL(w, r)
			default:
				s.sendErrorResponse(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
			}
			return
		}
		if path != "/" && !strings.HasPrefix(path, "/shorturls") {
			s.RedirectToURL(w, r)
			return
		}
		s.sendErrorResponse(w, http.StatusNotFound, "not_found", "Endpoint not found")
	})
}

func main() {
	hostname := "localhost"
	port := "8080"

	service := NewURLShortenerService(hostname, port)
	service.setupRoutes()

	sendSimpleLog("Starting URL Shortener Service")

	handler := LoggingMiddleware(http.DefaultServeMux)
	if err := http.ListenAndServe(fmt.Sprintf("%s:%s", hostname, port), handler); err != nil {
		sendDetailedLog("backend", "error", "main", fmt.Sprintf("Failed to start server: %s", err.Error()))
		os.Exit(1)
	}
}