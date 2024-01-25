package main

import (
	"crypto/md5"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	port            = ":4040"
	sessionDir      = "/etc/nginx/sessions/"
	blacklistFile   = "/etc/nginx/lwblack.txt"
	randomChars     = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	refreshInterval = 3 * time.Second
)

var (
	blacklistIPs  map[string]bool
	blacklistHash string
)

func main() {
	if err := loadBlacklist(); err != nil {
		log.Fatalf("Failed to load the blacklist: %s", err)
	}

	go checkBlacklistUpdates()

	http.HandleFunc("/", handler)
	log.Printf("Server listening on port %s", port)
	log.Fatal(http.ListenAndServe(port, nil))
}

func handler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	invalidCharRegex := regexp.MustCompile(`[^A-Za-z./]`)
	if invalidCharRegex.MatchString(r.URL.Path) {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	ip := getRealIP(r)
	if ip == "" {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	if isIPBlacklisted(ip) {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	if !isRequestValid(r) {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	if r.URL.Path == "/check" {
		cookie, err := r.Cookie("LW")
		if err == nil && cookie.Value != "" {
			sessionFile := getSessionFileName(cookie.Value)
			if _, err := os.Stat(sessionFile); err == nil {
				w.WriteHeader(http.StatusOK)
				return
			}
		}

		userAgent := r.Header.Get("User-Agent")
		if validateUserAgent(userAgent) {
			randomValue := generateRandomValue(27)
			sessionFile := getSessionFileName(randomValue)

			for {
				if _, err := os.Stat(sessionFile); os.IsNotExist(err) {
					break
				}
				randomValue = generateRandomValue(27)
				sessionFile = getSessionFileName(randomValue)
			}

			fileContent := fmt.Sprintf("%s+ip%s", userAgent, ip) // User-Agent + IP
			if err := ioutil.WriteFile(sessionFile, []byte(fileContent), 0644); err != nil {
				log.Printf("Failed to write session file: %s", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			http.SetCookie(w, &http.Cookie{
				Name:  "LW",
				Value: randomValue,
			})

			w.WriteHeader(http.StatusOK)
			return
		}
	}

	w.WriteHeader(http.StatusNotFound)
}

func isRequestValid(r *http.Request) bool {
	validMethods := []string{http.MethodGet, http.MethodPost, http.MethodHead}
	for _, method := range validMethods {
		if r.Method == method {
			return true
		}
	}
	return false
}

func validateUserAgent(userAgent string) bool {
	return true
}

func getSessionFileName(cookieValue string) string {
	return filepath.Join(sessionDir, cookieValue)
}

func generateRandomValue(length int) string {
	rand.Seed(time.Now().UnixNano())

	var sb strings.Builder
	for i := 0; i < length; i++ {
		randomIndex := rand.Intn(len(randomChars))
		sb.WriteByte(randomChars[randomIndex])
	}
	return sb.String()
}

func loadBlacklist() error {
	data, err := ioutil.ReadFile(blacklistFile)
	if err != nil {
		return err
	}

	blacklistHash = fmt.Sprintf("%x", md5.Sum(data))

	blacklistIPs = make(map[string]bool)
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		ip := strings.TrimSpace(line)
		if ip != "" {
			blacklistIPs[ip] = true
		}
	}

	return nil
}

func isIPBlacklisted(ip string) bool {
	if blacklistHash == "" {
		return false
	}

	hash := fmt.Sprintf("%x", md5.Sum([]byte(ip)))
	return hash == blacklistHash || blacklistIPs[ip]
}

func checkBlacklistUpdates() {
	for {
		time.Sleep(refreshInterval)
		if err := loadBlacklist(); err != nil {
			log.Printf("Failed to load the blacklist: %s", err)
		}
	}
}

func getRealIP(r *http.Request) string {
	forwardedFor := r.Header.Get("X-Forwarded-For")
	if forwardedFor != "" {
		ips := strings.Split(forwardedFor, ",")
		for _, ip := range ips {
			ip = strings.TrimSpace(ip)
			if isIPAddress(ip) {
				return ip
			}
		}
	}

	cfConnectingIP := r.Header.Get("CF-Connecting-IP")
	if cfConnectingIP != "" {
		return cfConnectingIP
	}

	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	return ip
}

func isIPAddress(ip string) bool {
	return net.ParseIP(ip) != nil
}
