// Package dualsession contains middleware for easy session management in Martini.
//
//  package main
//
//  import (
//    "github.com/go-martini/martini"
//    "github.com/sbtdkj1017/dualsession"
//  )
//
//  func main() {
// 	  m := martini.Classic()
//
// 	  dualsession := dualsession.New()
// 	  m.Use(dualsession)
// 	  m.Get("/", func(session dualsession.Session) string {
// 		  session.Username("hello", "world")
// 	  })
//    go m.RunOnAddr(":8080")
//    mHttps := martini.Classic()
//    mHttps.Use(dualsession)
//    http.ListenAndServeTLS(":8443", "cert.pem", "key.pem", mHttps)
//  }
package dualsession

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"log"
	"net/http"
	"time"

	"github.com/go-martini/martini"
)

func New() martini.Handler {
	sessions := make(map[string]*session)
	// record last clear time to clear session every hour
	lastClearTime := time.Now()
	var maxAgeInSeconds int = 3600 * 24

	return func(w http.ResponseWriter, req *http.Request, c martini.Context, l *log.Logger) {
		// clear old sessions
		if time.Since(lastClearTime).Hours() > 1 {
			clearOldSessions(sessions, maxAgeInSeconds, l)
		}
		// get sessionKeyName
		isHttps := req.TLS != nil // the only method to judge if https is from TLS attr (it cost me so much time)
		sessionKeyName := "sessionKey"
		if isHttps {
			sessionKeyName = "sessionKeyHttps"
		}
		l.Println("sessionKeyName = ", sessionKeyName)
		// get sessionKey by sessionKeyName from cookie
		cookie, err := req.Cookie(sessionKeyName)
		sessionKey := ""
		if err == nil {
			sessionKey = cookie.Value
			if isHttps {
				sessionKeyHash := sha256.Sum256([]byte(sessionKey))
				sessionKey = hex.EncodeToString(sessionKeyHash[:])
			}
		}
		l.Println("sessionKey[after] = ", sessionKey)
		// get session by sessionKey
		var s *session
		if v, ok := sessions[sessionKey]; ok {
			s = v
		} else { // if session not exist, then new it
			s = &session{time.Now(), make(map[string]interface{}), false}
			s.store["username"] = "guest"
			// generate sessionKey randomly
			b := make([]byte, 32)
			_, err := rand.Read(b)
			if err != nil {
				panic(err.Error())
			}
			sessionKeyHttps := hex.EncodeToString(b)
			s.store["sessionKeyHttps"] = sessionKeyHttps
			// session key for HTTP (not HTTPS) is hashed for securety
			sessionKeySha256 := sha256.Sum256([]byte(sessionKeyHttps))
			sessionKey := hex.EncodeToString(sessionKeySha256[:])
			// save session by sessionKey
			sessions[sessionKey] = s
			// set cookie
			cookieUsername := http.Cookie{Name: "username", Value: "guest", Path: "/"}
			http.SetCookie(w, &cookieUsername)
			cookieSessionKey := http.Cookie{Name: "sessionKey", Value: sessionKey, Path: "/", HttpOnly: true}
			http.SetCookie(w, &cookieSessionKey)
			if isHttps { // sessionKeyHttps can only be set under HTTPS
				cookieSessionKeyHttps := http.Cookie{Name: "sessionKeyHttps", Value: sessionKeyHttps, Path: "/",
					HttpOnly: true, Secure: true}
				http.SetCookie(w, &cookieSessionKeyHttps)
			}
			l.Println("add session: sessionKey = ", sessionKey)
		}
		// Map to the Session interface
		c.MapTo(s, (*Session)(nil))

		c.Next()
	}
}

func clearOldSessions(sessions map[string]*session, maxAgeInSeconds int, l *log.Logger) {
	for k, v := range sessions {
		if time.Since(v.LastAccess).Seconds() > float64(maxAgeInSeconds) {
			l.Println("clear old session. key = ", k)
			delete(sessions, k)
		}
	}
}

// Session stores the values and optional configuration for a session
type Session interface {
	// Get returns the session value associated to the given key.
	Get(key string) interface{}
	// Set sets the session value associated to the given key.
	Set(key string, val interface{})
	// Set as authenticated
	SetAuthenticated(w http.ResponseWriter, username string)
}

type session struct {
	LastAccess time.Time
	store      map[string]interface{}
	authenticated     bool
}

func (s *session) Get(key string) interface{} {
	return s.store[key]
}

func (s *session) Set(key string, val interface{}) {
	s.store[key] = val
}

func (s *session) SetAuthenticated(w http.ResponseWriter, username string) {
	s.authenticated = true
	s.store["username"] = username
	// set cookie
	cookie := http.Cookie{Name: "username", Value: username, Path: "/"}
	http.SetCookie(w, &cookie)
}
