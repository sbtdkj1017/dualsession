// Package dualsession contains middleware for easy session management in Martini.
// It's safe for concurrent go routines.
// Why dual? Because two session key will be maintained, one for http, one for https,
// and any session key can be used to find session on server side. For speed, session
// key for http will be used automatically in HTTP condition. For safety, session key
// for https will only used in HTTPS condition.
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
//    http.ListenAndServeTLS(":8443", "cert.pem", "key.pem", m)
//  }
//
// When http request is processed by this middleware, a new session will be created
// and cookies with sessionKey will be set. If authenticated, it is strongly
// recomended to call SetAuthenticated function, it will write "userid" to both session
// and cookie, and set authenticated flag. Then you can judge if authenticated by
// userid (userid is null or empty for unauthenticated user).
//
// Here is an example for Session plugin in http handler
//  func foo(w http.ResponseWriter, req *http.Request, session dualsession.Session) {
//    authenticating here
//    session.SetAuthenticated(w, userid)
//  }
package dualsession

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"html"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/go-martini/martini"
)

// create a new martini middleware object
func New(options Options) martini.Handler {
	options.setDefault()
	sessions := make(map[string]*session)
	mutex := &sync.Mutex{}
	// record last clear time to clear session every hour
	lastClearTime := time.Now()

	return func(w http.ResponseWriter, req *http.Request, c martini.Context, l *log.Logger) {
		// clear old sessions
		if time.Since(lastClearTime).Hours() > 1 {
			mutex.Lock()
			clearOldSessions(sessions, l)
			mutex.Unlock()
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
		mutex.Lock()
		if v, ok := sessions[sessionKey]; ok {
			mutex.Unlock()
			s = v
			s.LastAccess = time.Now()
		} else { // if session not exist, then new it
			mutex.Unlock()
			s = &session{time.Now(), options.MaxAge, make(map[string]interface{}), false}
			s.store["userid"] = ""
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
			s.store["sessionKey"] = sessionKey
			// save session by sessionKey
			mutex.Lock()
			sessions[sessionKey] = s
			mutex.Unlock()
			// set cookie
			cookieUserId := http.Cookie{Name: "userid", Value: "", Path: "/"}
			http.SetCookie(w, &cookieUserId)
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

type Options struct {
	// Max age in seconds that the session will be maintained without any operation.
	// But the "MaxAge" of cookie is still set to 0 for safety. If you want to
	// keep cookie for specified time, call SetCookieMaxAge() when authenticated
	MaxAge int
}

func (o *Options) setDefault() {
	if (o.MaxAge == 0) {
		o.MaxAge = 24 * 3600
	}
}

func clearOldSessions(sessions map[string]*session, l *log.Logger) {
	l.Println("Begin clear old sessions. size = ", len(sessions))
	for k, v := range sessions {
		if time.Since(v.LastAccess).Seconds() > float64(v.MaxAge) {
			l.Println("clear old session. key = ", k)
			delete(sessions, k)
		}
	}
	l.Println("End clear old sessions. size = ", len(sessions))
}

// Session stores the values and optional configuration for a session
type Session interface {
	// Get returns the session value associated to the given key.
	Get(key string) interface{}
	// Set sets the session value associated to the given key.
	Set(key string, val interface{})
	// Set as authenticated
	SetAuthenticated(w http.ResponseWriter, userid string)
	// Set age of both session and cookie. http.Request is only used to judge if HTTPS
	// It should be called after SetAuthenticated
	SetSessionAge(w http.ResponseWriter, req *http.Request, ageSeconds int)
	// Get if authenticated
	Authenticated() bool
}

type session struct {
	LastAccess    time.Time
	MaxAge        int
	store         map[string]interface{}
	authenticated bool
}

func (s *session) Get(key string) interface{} {
	return s.store[key]
}

func (s *session) Set(key string, val interface{}) {
	s.store[key] = val
}

func (s *session) SetAuthenticated(w http.ResponseWriter, userid string) {
	s.authenticated = true
	s.store["userid"] = userid
	// set cookie
	cookie := http.Cookie{Name: "userid", Value: html.EscapeString(userid), Path: "/"}
	http.SetCookie(w, &cookie)
}

func (s *session) SetSessionAge(w http.ResponseWriter, req *http.Request, ageSeconds int) {
	s.authenticated = true
	s.MaxAge = ageSeconds
	isHttps := req.TLS != nil
	var expired time.Time
	if ageSeconds != 0 {
		expired = time.Now().Add(time.Duration(ageSeconds) * time.Second)
	}
	// set cookie
	cookieUserId := http.Cookie{Name: "userid", Value: html.EscapeString(s.store["userid"].(string)),
		Path: "/", MaxAge: ageSeconds, Expires: expired}
	http.SetCookie(w, &cookieUserId)
	cookieSessionKey := http.Cookie{Name: "sessionKey", Value: s.store["sessionKey"].(string),
		Path: "/", HttpOnly: true, MaxAge: ageSeconds, Expires: expired}
	http.SetCookie(w, &cookieSessionKey)
	if isHttps { // sessionKeyHttps can only be set under HTTPS
		cookieSessionKeyHttps := http.Cookie{Name: "sessionKeyHttps", Value: s.store["sessionKeyHttps"].(string),
			Path: "/", HttpOnly: true, Secure: true, MaxAge: ageSeconds, Expires: expired}
		http.SetCookie(w, &cookieSessionKeyHttps)
	}
}

func (s *session) Authenticated() bool {
	return s.authenticated
}
