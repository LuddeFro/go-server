package main

//TODO , threading
//TODO , prepare all statements
import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/alexjlockwood/gcm"
	apns "github.com/anachronistic/apns"
	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"net/smtp"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"text/template"
	"time"
	"unicode/utf8"
)

func checkErr(err error, w http.ResponseWriter) (bol bool) {
	if err != nil {
		response := Response{
			Success: 0,
			Error:   err.Error(),
		}
		json.NewEncoder(w).Encode(response)
		return false
	}
	return true
}

func validateEmail(email string, w http.ResponseWriter) (bol bool) {
	Re := regexp.MustCompile(`^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,4}$`)
	if Re.MatchString(email) {
		return true
	} else {
		response := Response{
			Success: 0,
			Error:   "Invalid email address",
		}
		json.NewEncoder(w).Encode(response)
		return false
	}
}

func handle404(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "(404) Hi there, I love %s! Unfortunately, I couldn't find it :/", r.URL.Path[1:])
}

type Response struct {
	Success         int    `json:"success"`
	Error           string `json:"error,omitempty"`
	Device_id       int    `json:"device_id,omitempty"`
	Session_token   string `json:"session_token,omitempty"`
	Current_version string `json:"current_version,omitempty"`
	Download_link   string `json:"download_link,omitempty"`
	Game            int    `json:"game,omitempty"`
	Status          int    `json:"status,omitempty"`
	Accept_before   int    `json:"accept_before,omitempty"`
	Time            int32  `json:"time,omitempty"`
	IP              string `json:"ip,omitempty"`
}

var letters = []rune("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func randSeq(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	//fmt.Fprintf(w, "logging in?\n")
	r.ParseForm()
	//fmt.Fprintf(w, "parsed form")
	em := strings.ToLower(r.Form.Get("email"))
	if !validateEmail(em, w) {
		return
	}

	if !checkKey(r.Form.Get("key"), w) {
		return
	}

	pw := []byte(r.Form.Get("password"))
	if len(r.Form.Get("password")) < 6 {
		response := Response{
			Success: 0,
			Error:   "Password too short",
		}
		json.NewEncoder(w).Encode(response)
		return
	}
	di, err := strconv.ParseInt(r.Form.Get("device_id"), 10, 0) //optional
	pt := r.Form.Get("push_token")                              //only mobile
	sys := strings.Split(r.URL.Path[1:], "/")[0]
	//fmt.Fprintf(w, "user: %s, pwd: %s, di: %s, pt: %s, sys: %s", em, pw, di, pt, sys)

	//fmt.Fprintf(w, "connected to DB")

	//check email exists in users
	rows, err := db.Query("SELECT user_id, password FROM users WHERE email=? LIMIT 1", em)
	//fmt.Fprintf(w, "%s", rows)
	if !checkErr(err, w) {
		return
	}
	//fmt.Fprintf(w, "Checkat error")
	n := 0
	var user_id int
	var hpwstring string
	//fmt.Fprintf(w, "hpw:%s, uid:%d, n:%d", hpwstring, user_id, n)

	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			n++
			err = rows.Scan(&user_id, &hpwstring)
		}
	}

	if n == 0 {
		//fmt.Fprintf(w, "n=======0")
		response := Response{
			Success: 0,
			Error:   "Invalid email address",
		}
		json.NewEncoder(w).Encode(response)
		return
	}

	hpw := []byte(hpwstring)

	//bruteforce check
	//first clear old rows
	stmt, err := db.Prepare("delete from login_attempts where user_id=? and ?-time>600")
	if !checkErr(err, w) {
		return
	}
	_, err = stmt.Exec(user_id, int32(time.Now().Unix()))
	if !checkErr(err, w) {
		return
	}
	//fmt.Fprintf(w, "pw:%s di:%s pt:%s sys:%s hpw:%s", pw, di, pt, sys, hpw)

	//check how many rows remain
	rows2, err2 := db.Query("SELECT * FROM login_attempts WHERE user_id=?", user_id)
	checkErr(err2, w)
	n2 := 0
	if rows2 != nil {
		defer rows2.Close()
		for rows2.Next() {
			n2++
		}
	}

	//fmt.Fprintf(w, "bruteforce test")
	if n2 >= 10 {
		//bruteforcing
		//return error
		response := Response{
			Success: 0,
			Error:   "Too many recent login attempts. This account has been locked for up to 10 minutes.",
		}
		json.NewEncoder(w).Encode(response)
		return
	}

	//fmt.Fprintf(w, "checking passwords")
	//check password
	erro := bcrypt.CompareHashAndPassword(hpw, pw)
	if erro != nil {
		//password mismatch
		//insert entry in login_attempts
		stmt, err := db.Prepare("INSERT login_attempts SET user_id=?,time=?")
		if !checkErr(err, w) {
			return
		}
		_, err = stmt.Exec(user_id, int32(time.Now().Unix()))
		if !checkErr(err, w) {
			return
		}

		//return error
		response := Response{
			Success: 0,
			Error:   "Invalid password",
		}
		json.NewEncoder(w).Encode(response)
		return
	}

	//login info valid

	//generate st
	st := []byte(randSeq(32))
	hst, err := bcrypt.GenerateFromPassword(st, 11)
	if !checkErr(err, w) {
		return
	}

	//update appropriate tables and give appropriate response
	table := ""
	if sys == "ios" {
		table = "iphones"
	} else if sys == "android" {
		table = "androids"
	} else if sys == "computer" {
		table = "computers"
	}
	var buffer bytes.Buffer

	if di == 0 {
		//insert new entry
		buffer.WriteString("INSERT ")
		buffer.WriteString(table)
		if sys == "computer" {
			//is computer

			stmt, err := db.Prepare("update computers set user_id=?, session_token=? where user_id=?")
			if !checkErr(err, w) {
				return
			}

			_, err = stmt.Exec(nil, "", user_id)
			if !checkErr(err, w) {
				return
			}

			buffer.WriteString(" SET user_id=?,status=?,game=?,session_token=?")
			stmt, err = db.Prepare(buffer.String())
			if !checkErr(err, w) {
				return
			}
			res, err := stmt.Exec(user_id, 0, 0, hst)
			if !checkErr(err, w) {
				return
			}
			di, err = res.LastInsertId()
			if !checkErr(err, w) {
				return
			}
		} else {
			//is mobile, insert push token
			stmt, err := db.Prepare("update " + table + " set user_id=?, session_token=?, push_token=? where push_token=?")
			if !checkErr(err, w) {
				return
			}

			_, err = stmt.Exec(nil, "", "", pt)
			if !checkErr(err, w) {
				return
			}

			buffer.WriteString(" SET user_id=?,push_token=?,session_token=?")
			stmt, err = db.Prepare(buffer.String())
			if !checkErr(err, w) {
				return
			}
			res, err := stmt.Exec(user_id, pt, hst)
			if !checkErr(err, w) {
				return
			}
			di, err = res.LastInsertId()
			if !checkErr(err, w) {
				return
			}
		}
		// return device id, session token and success
		response := Response{
			Success:       1,
			Device_id:     int(di),
			Session_token: string(st),
			Time:          int32(time.Now().Unix()),
		}
		json.NewEncoder(w).Encode(response)

	} else {
		//device has entry already, update existing
		buffer.WriteString("UPDATE ")
		buffer.WriteString(table)
		if sys == "computer" {
			//is computer
			//log out other computers
			stmt, err := db.Prepare("update computers set user_id=?, session_token=? where user_id=?")
			if !checkErr(err, w) {
				return
			}

			_, err = stmt.Exec(nil, "", user_id)
			if !checkErr(err, w) {
				return
			}

			buffer.WriteString(" SET user_id=?,status=?,game=?,session_token=? WHERE device_id=?")
			stmt, err = db.Prepare(buffer.String())
			if !checkErr(err, w) {
				return
			}
			_, err = stmt.Exec(user_id, 0, 0, hst, di)
			if !checkErr(err, w) {
				return
			}
		} else {
			//is mobile, insert push token
			buffer.WriteString(" SET user_id=?,push_token=?,session_token=? WHERE device_id=?")
			stmt, err := db.Prepare(buffer.String())
			if !checkErr(err, w) {
				return
			}
			_, err = stmt.Exec(user_id, pt, hst, di)
			if !checkErr(err, w) {
				return
			}
		}
		// return device id, session token and success
		response := Response{
			Success:       1,
			Session_token: string(st),
			Time:          int32(time.Now().Unix()),
		}
		json.NewEncoder(w).Encode(response)
	}

	//returned Optional(device_id), success, Optional(error), session_token
}

func checkSession(di int, s_t string, sys string, w http.ResponseWriter) (err error, uid int) {
	st := []byte(s_t)
	var table string
	if sys == "ios" {
		table = "iphones"
	} else if sys == "android" {
		table = "androids"
	} else if sys == "computer" {
		table = "computers"
	}

	qry := "SELECT session_token, user_id FROM " + table + " WHERE device_id=?"
	rows, err := db.Query(qry, di)
	if !checkErr(err, w) {
		return err, 0
	}

	var hststring string
	var u_id int
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			err = rows.Scan(&hststring, &u_id)
			if err != nil {
				return err, u_id
			}
		}
	}

	hst := []byte(hststring)
	err = bcrypt.CompareHashAndPassword(hst, st)
	if err == nil {
		//st match
		return nil, u_id
	} else {
		//st mismatch
		return err, u_id
	}

}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	if !checkKey(r.Form.Get("key"), w) {
		return
	}
	di, err := strconv.ParseInt(r.Form.Get("device_id"), 10, 0)
	st := r.Form.Get("session_token")
	sys := strings.Split(r.URL.Path[1:], "/")[0]
	err, _ = checkSession(int(di), st, sys, w)
	if !checkErr(err, w) {
		return
	}
	//fmt.Fprintf(w, "di: %s, st: %s, sys: %s", di, st, sys)
	var buffer bytes.Buffer
	buffer.WriteString("UPDATE ")
	if sys == "computer" {
		buffer.WriteString("computers")
	} else if sys == "ios" {
		buffer.WriteString("iphones")
	} else if sys == "android" {
		buffer.WriteString("androids")
	}
	if sys == "computer" {
		buffer.WriteString(" SET user_id=?, session_token=?, status=?, game=? WHERE device_id=?")
		stmt, err := db.Prepare(buffer.String())
		if !checkErr(err, w) {
			return
		}
		_, err = stmt.Exec(nil, "", 0, 0, di)
		if !checkErr(err, w) {
			return
		}
	} else {
		buffer.WriteString(" SET user_id=?, session_token=?, push_token=? WHERE device_id=?")
		stmt, err := db.Prepare(buffer.String())
		if !checkErr(err, w) {
			return
		}
		_, err = stmt.Exec(nil, "", "", di)
		if !checkErr(err, w) {
			return
		}
	}
	response := Response{
		Success: 1,
	}
	json.NewEncoder(w).Encode(response)
	//returned success
}

func handleRegister(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	if !checkKey(r.Form.Get("key"), w) {
		return
	}
	em := strings.ToLower(r.Form.Get("email"))
	if !validateEmail(em, w) {
		return
	}
	pw := []byte(r.Form.Get("password"))
	if len(r.Form.Get("password")) < 6 {
		response := Response{
			Success: 0,
			Error:   "Password too short",
		}
		json.NewEncoder(w).Encode(response)
		return
	}
	di, err := strconv.ParseInt(r.Form.Get("device_id"), 10, 0) //optional
	pt := r.Form.Get("push_token")                              //only mobile
	sys := strings.Split(r.URL.Path[1:], "/")[0]
	//fmt.Fprintf(w, "user: %s, pwd: %s, di: %s, pt: %s, sys: %s", em, pw, di, pt, sys)

	//check email exists in users
	rows, err := db.Query("SELECT * FROM users WHERE email=? LIMIT 1", em)
	if !checkErr(err, w) {
		return
	}
	n := 0
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			n++
			break
		}
	}

	if n != 0 {
		response := Response{
			Success: 0,
			Error:   "An account already exists with the specified email address",
		}
		json.NewEncoder(w).Encode(response)
		return
	}

	//hash password
	hpw, err := bcrypt.GenerateFromPassword(pw, 11)
	if !checkErr(err, w) {
		return
	}

	//proceed with registration

	//generate st and hst
	st := []byte(randSeq(32))
	hst, err := bcrypt.GenerateFromPassword(st, 11)
	if !checkErr(err, w) {
		return
	}

	//insert entry to users
	stmt, err := db.Prepare("INSERT users SET email=?,password=?")
	if !checkErr(err, w) {
		return
	}
	res1, err := stmt.Exec(em, hpw)
	if !checkErr(err, w) {
		return
	}
	user_id, err := res1.LastInsertId()
	if !checkErr(err, w) {
		return
	}

	//update appropriate tables as if logging in and give appropriate response
	table := ""
	if sys == "ios" {
		table = "iphones"
	} else if sys == "android" {
		table = "androids"
	} else if sys == "computer" {
		table = "computers"
	}
	var buffer bytes.Buffer

	if di == 0 {
		//insert new entry
		buffer.WriteString("INSERT ")
		buffer.WriteString(table)
		if sys == "computer" {
			//is computer
			buffer.WriteString(" SET user_id=?,status=?,game=?,session_token=?")
			stmt, err := db.Prepare(buffer.String())
			if !checkErr(err, w) {
				return
			}
			res, err := stmt.Exec(user_id, 0, 0, hst)
			if !checkErr(err, w) {
				return
			}
			di, err = res.LastInsertId()
			if !checkErr(err, w) {
				return
			}
		} else {
			//is mobile, insert push token
			stmt, err := db.Prepare("update " + table + " set user_id=?, session_token=?, push_token=? where push_token=?")
			if !checkErr(err, w) {
				return
			}

			_, err = stmt.Exec(nil, "", "", pt)
			if !checkErr(err, w) {
				return
			}

			buffer.WriteString(" SET user_id=?,push_token=?,session_token=?")
			stmt, err = db.Prepare(buffer.String())
			if !checkErr(err, w) {
				return
			}
			res, err := stmt.Exec(user_id, pt, hst)
			if !checkErr(err, w) {
				return
			}
			di, err = res.LastInsertId()
			if !checkErr(err, w) {
				return
			}
		}
		// return device id, session token and success
		response := Response{
			Success:       1,
			Device_id:     int(di),
			Session_token: string(st),
		}
		json.NewEncoder(w).Encode(response)

	} else {
		//device has entry already, update existing
		buffer.WriteString("UPDATE ")
		buffer.WriteString(table)
		if sys == "computer" {
			//is computer
			buffer.WriteString(" SET user_id=?,status=?,game=?,session_token=? WHERE device_id=?")
			stmt, err := db.Prepare(buffer.String())
			if !checkErr(err, w) {
				return
			}
			_, err = stmt.Exec(user_id, 0, 0, hst, di)
			if !checkErr(err, w) {
				return
			}
		} else {
			//is mobile, insert push token
			buffer.WriteString(" SET user_id=?,push_token=?,session_token=? WHERE device_id=?")
			stmt, err := db.Prepare(buffer.String())
			if !checkErr(err, w) {
				return
			}
			_, err = stmt.Exec(user_id, pt, hst, di)
			if !checkErr(err, w) {
				return
			}
		}
		// return device id, session token and success
		response := Response{
			Success:       1,
			Session_token: string(st),
		}
		json.NewEncoder(w).Encode(response)
	}
	//returned Optional(device_id), success, Optional(error), session_token
}

func handleSetStatus(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	if !checkKey(r.Form.Get("key"), w) {
		return
	}
	sa, err := strconv.ParseInt(r.Form.Get("status"), 10, 0)
	st := r.Form.Get("session_token")
	di, err := strconv.ParseInt(r.Form.Get("device_id"), 10, 0)
	var gm int
	gmt, err := strconv.ParseInt(r.Form.Get("game"), 10, 0) //optional
	gm = int(gmt)
	sys := strings.Split(r.URL.Path[1:], "/")[0]

	//fmt.Fprintf(w, "status: %s, st: %s, di: %s, gm: %s", sa, st, di, gm)
	//check session
	err, user_id := checkSession(int(di), st, sys, w)
	if !checkErr(err, w) {
		return
	}

	//update status
	stmt, err := db.Prepare("update computers set status=?, game=?, status_timestamp=?, status_ip=INET_ATON('?') where device_id=?")
	if !checkErr(err, w) {
		return
	}

	_, err = stmt.Exec(sa, gm, int32(time.Now().Unix()), myip, di)
	if !checkErr(err, w) {
		return
	}

	if r.Form.Get("status") == "4" {

		rows, err := db.Query("SELECT auto_accept FROM users WHERE user_id=? LIMIT 1", user_id)
		//fmt.Fprintf(w, "%s", rows)
		if !checkErr(err, w) {
			return
		}

		var aa int

		if rows != nil {
			defer rows.Close()
			for rows.Next() {
				err = rows.Scan(&aa)
			}
		}

		pushQueuePop(w, gm, user_id, db, aa)

		return
	}

	response := Response{
		Success: 1,
	}
	json.NewEncoder(w).Encode(response)
	//return success, Optional(error)

}

func handleGetStatus(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	if !checkKey(r.Form.Get("key"), w) {
		return
	}
	di, err := strconv.ParseInt(r.Form.Get("device_id"), 10, 0)
	st := r.Form.Get("session_token")
	sys := strings.Split(r.URL.Path[1:], "/")[0]
	//fmt.Fprintf(w, "di: %s, st: %s, sys: %s", di, st, sys)

	//check session
	err, user_id := checkSession(int(di), st, sys, w)
	if !checkErr(err, w) {
		return
	}

	rows, err := db.Query("SELECT game, status, status_timestamp, INET_NTOA(`status_ip`) FROM computers WHERE user_id=? LIMIT 1", user_id)
	if !checkErr(err, w) {
		return
	}
	resp := Response{
		Success: 1,
		Game:    0,
		Status:  0,
	}
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var status int
			var game int
			var timestamp int32
			var ip string
			err = rows.Scan(&game, &status, &timestamp, &ip)
			if !checkErr(err, w) {
				return
			}
			if int32(time.Now().Unix())-timestamp < 130 {
				var ab int
				ab = 0
				if status == 4 {
					if game == 1 {
						ab = int(timestamp) + 45
					} else if game == 3 {
						ab = int(timestamp) + 20
					} else if game == 5 {
						ab = int(timestamp) + 10
					}
				}
				resp = Response{
					Success:       1,
					Game:          game,
					Status:        status,
					Accept_before: ab,
					IP:            ip,
				}
			}
		}
	}

	json.NewEncoder(w).Encode(resp)

	//return success, Optional(error), status, Optional(game)
}

func handleAccept(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	if !checkKey(r.Form.Get("key"), w) {
		return
	}
	di, err := strconv.ParseInt(r.Form.Get("device_id"), 10, 0)
	st := r.Form.Get("session_token")
	sys := strings.Split(r.URL.Path[1:], "/")[0]
	acc, err := strconv.ParseInt(r.Form.Get("accept"), 10, 0)

	//check session
	err, user_id := checkSession(int(di), st, sys, w)
	if !checkErr(err, w) {
		return
	}
	_, ok := channels[user_id]
	if !ok {
		resp := Response{
			Success: 0,
		}
		json.NewEncoder(w).Encode(resp)
		return
	}
	if acc != 0 {
		//accept
		channels[user_id] <- "accept"
	} else {
		//decline
		channels[user_id] <- "decline"
	}

	//fmt.Fprintf(w, "di: %s, st: %s, sys: %s", di, st, sys)
	resp := Response{
		Success: 1,
	}
	json.NewEncoder(w).Encode(resp)
}

func handleUpdateToken(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	if !checkKey(r.Form.Get("key"), w) {
		return
	}
	st := r.Form.Get("session_token")
	di, err := strconv.ParseInt(r.Form.Get("device_id"), 10, 0)
	pt := r.Form.Get("push_token")
	sys := strings.Split(r.URL.Path[1:], "/")[0]
	//fmt.Fprintf(w, "st: %s, di: %s, pt: %s, sys: %s", st, di, pt, sys)

	//check session
	err, _ = checkSession(int(di), st, sys, w)
	if !checkErr(err, w) {
		return
	}

	var table string

	if sys == "ios" {
		table = "iphones"
	} else if sys == "android" {
		table = "androids"
	}

	stmt, err := db.Prepare("update " + table + " set push_token=? where device_id=?")
	if !checkErr(err, w) {
		return
	}

	_, err = stmt.Exec(pt, di)
	if !checkErr(err, w) {
		return
	}

	response := Response{
		Success: 1,
	}
	json.NewEncoder(w).Encode(response)

	//returned success, Optional(error)
}

func handleUpdateAutoAccept(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	if !checkKey(r.Form.Get("key"), w) {
		return
	}
	st := r.Form.Get("session_token")
	di, err := strconv.ParseInt(r.Form.Get("device_id"), 10, 0)
	sys := strings.Split(r.URL.Path[1:], "/")[0]
	aa, err := strconv.ParseInt(r.Form.Get("auto_accept"), 10, 0)
	if aa != 0 {
		aa = 1
	}
	//fmt.Fprintf(w, "st: %s, di: %s, pt: %s, sys: %s", st, di, pt, sys)

	//check session
	err, uid := checkSession(int(di), st, sys, w)
	if !checkErr(err, w) {
		return
	}

	stmt, err := db.Prepare("update users set auto_accept=? where user_id=?")
	if !checkErr(err, w) {
		return
	}

	_, err = stmt.Exec(aa, uid)
	if !checkErr(err, w) {
		return
	}

	response := Response{
		Success: 1,
	}
	json.NewEncoder(w).Encode(response)

	//returned success, Optional(error)
}

func handleGetAutoAccept(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	if !checkKey(r.Form.Get("key"), w) {
		return
	}
	st := r.Form.Get("session_token")
	di, err := strconv.ParseInt(r.Form.Get("device_id"), 10, 0)
	sys := strings.Split(r.URL.Path[1:], "/")[0]
	//fmt.Fprintf(w, "st: %s, di: %s, pt: %s, sys: %s", st, di, pt, sys)

	//check session
	err, uid := checkSession(int(di), st, sys, w)
	if !checkErr(err, w) {
		return
	}

	rows, err := db.Query("SELECT auto_accept FROM users WHERE user_id=? LIMIT 1", uid)
	//fmt.Fprintf(w, "%s", rows)
	if !checkErr(err, w) {
		return
	}

	var aa int

	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			err = rows.Scan(&aa)
		}
	}

	response := Response{
		Success: aa,
		Error:   "accept",
	}
	json.NewEncoder(w).Encode(response)

	//returned success, Optional(error)
}

func pushQueuePop(w http.ResponseWriter, g int, user_id int, db *sql.DB, aa int) {
	var ab int32
	ab = 0
	var maxwait int
	maxwait = 0
	gamestring := "Matchmaking"
	switch {
	case g == 0:
		gamestring = "Matchmaking"
		break
	case g == 1:
		gamestring = "Dota2"
		ab = int32(time.Now().Unix()) + 45
		maxwait = 45
		break
	case g == 2:
		gamestring = "HoN"
		break
	case g == 3:
		gamestring = "CS:GO"
		maxwait = 20
		ab = int32(time.Now().Unix()) + 20
		break
	case g == 4:
		gamestring = "HotS"
		break
	case g == 5:
		gamestring = "LoL"
		maxwait = 10
		ab = int32(time.Now().Unix()) + 10
		break
	case g > 5 || g < 0:
		gamestring = "Matchmaking"
		break
	}

	//push to all iPhones
	rows, err := db.Query("SELECT push_token FROM iphones WHERE user_id=?", user_id)
	if !checkErr(err, w) {
		return
	}
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var token string
			err = rows.Scan(&token)
			if !checkErr(err, w) {
				return
			}
			if utf8.RuneCountInString(token) > 10 {
				//pushit ios
				payload := apns.NewPayload()
				payload.Alert = gamestring + " queue ended!"
				payload.Sound = "NotifCustom1.aif"

				pn := apns.NewPushNotification()
				pn.AddPayload(payload)
				pn.DeviceToken = token

				pn.Set("accept_before", ab)
				pn.Set("ip", myip)
				//DEVELOPMENT
				//client := apns.NewClient("gateway.sandbox.push.apple.com:2195", "/home/ubuntu/Keys/dev-push/GameQiOS-Dev-Cert.pem", "/home/ubuntu/Keys/dev-push/GameQiOS-Dev-Key-Unencrypted.pem")
				//PRODUCTION
				client := apns.NewClient("gateway.push.apple.com:2195", "/home/ubuntu/Keys/prod-push/GameQiOS-Prod-Cert.pem", "/home/ubuntu/Keys/prod-push/GameQiOS-Prod-Key-Unencrypted.pem")
				/*
					Cert locations:

					/home/ubuntu/Keys/prod-push/GameQiOS-Prod-Key-Unencrypted.pem
					/home/ubuntu/Keys/prod-push/GameQiOS-Prod-Cert.pem

					/home/ubuntu/Keys/dev-push/GameQiOS-Dev-Key-Unencrypted.pem
					/home/ubuntu/Keys/dev-push/GameQiOS-Dev-Cert.pem
				*/

				_ = client.Send(pn)
				//smths := smth.
				response := Response{
					Success: 1,
				}
				json.NewEncoder(w).Encode(response)
				/*
				   alert, _ := pn.PayloadString()
				   fmt.Println("  Alert:", alert)
				   fmt.Println("Success:", resp.Success)
				   fmt.Println("  Error:", resp.Error)*/
			}

		}
	}

	//push to all Androids

	rows2, err := db.Query("SELECT push_token FROM androids WHERE user_id=?", user_id)
	if !checkErr(err, w) {
		return
	}
	for rows2.Next() {

		responsee := Response{
			Success: 1,
			Error:   "Android",
		}
		json.NewEncoder(w).Encode(responsee)

		var token string
		err = rows2.Scan(&token)
		if !checkErr(err, w) {
			return
		}
		if utf8.RuneCountInString(token) > 10 {
			data := map[string]interface{}{"message": "Queue ended for " + gamestring + "!"}
			msg := gcm.NewMessage(data, token)

			// Create a Sender to send the message.
			sender := &gcm.Sender{ApiKey: "AIzaSyC2NvDf3WUbz_ekl6nR2CcpucmTRNmtPcg"}

			// Send the message and receive the response after at most two retries.
			_, err := sender.Send(msg, 2)
			if err != nil {
				response := Response{
					Success: 0,
					Error:   "Failed to send message:" + err.Error(),
				}
				json.NewEncoder(w).Encode(response)
				return
			}

		}

	}
	var aaS string

	if aa != 0 {
		aaS = "auto"
	} else {
		ch := make(chan string)
		channels[user_id] = ch
		timeout := time.After(time.Duration(maxwait) * time.Second)
		select {
		case r := <-ch:
			aaS = r
		case <-timeout:
			aaS = "accept response timeout"
		}
		delete(channels, user_id)
		close(ch)
	}
	response := Response{
		Success: 1,
		Error:   aaS,
	}
	json.NewEncoder(w).Encode(response)

	//return success, Optional(error)
}

func handleVersionControl(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	if !checkKey(r.Form.Get("key"), w) {
		return
	}
	os := r.Form.Get("os")
	sys := strings.Split(r.URL.Path[1:], "/")[0]
	//fmt.Fprintf(w, "os: %s, sys: %s", os, sys)
	if sys == "ios" {
		response := Response{
			Success:         1,
			Current_version: "0.0.1",
			Download_link:   "http://server.gameq.io/downloads/ios",
		}
		json.NewEncoder(w).Encode(response)
	} else if sys == "android" {
		response := Response{
			Success:         1,
			Current_version: "0.0.1",
			Download_link:   "http://server.gameq.io/downloads/android",
		}
		json.NewEncoder(w).Encode(response)
	} else if sys == "computer" {
		if os == "mac" {
			response := Response{
				Success:         1,
				Current_version: "0.0.1",
				Download_link:   "http://server.gameq.io/downloads/osx",
			}
			json.NewEncoder(w).Encode(response)
		} else if os == "pc" {
			response := Response{
				Success:         1,
				Current_version: "0.0.1",
				Download_link:   "http://server.gameq.io/downloads/windows",
			}
			json.NewEncoder(w).Encode(response)
		}
	}
	//returned success, Optional(error)
}

func handleUpdatePassword(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	if !checkKey(r.Form.Get("key"), w) {
		return
	}
	di, err := strconv.ParseInt(r.Form.Get("device_id"), 10, 0)
	st := r.Form.Get("session_token")
	em := strings.ToLower(r.Form.Get("email"))
	if !validateEmail(em, w) {
		return
	}
	pw := []byte(r.Form.Get("password"))
	if len(r.Form.Get("password")) < 6 {
		response := Response{
			Success: 0,
			Error:   "Old password too short",
		}
		json.NewEncoder(w).Encode(response)
		return
	}
	if len(r.Form.Get("new_password")) < 6 {
		response := Response{
			Success: 0,
			Error:   "New password too short",
		}
		json.NewEncoder(w).Encode(response)
		return
	}
	npw := []byte(r.Form.Get("new_password"))

	sys := strings.Split(r.URL.Path[1:], "/")[0]

	//check session
	err, user_id := checkSession(int(di), st, sys, w)
	if !checkErr(err, w) {
		return
	}

	rows, err := db.Query("SELECT password FROM users WHERE user_id=? LIMIT 1", user_id)
	if !checkErr(err, w) {
		return
	}
	var hpwstring string

	if rows != nil {
		defer rows.Close()
		for rows.Next() {

			err = rows.Scan(&hpwstring)
			if !checkErr(err, w) {
				return
			}
		}
	}

	hpw := []byte(hpwstring)

	err = bcrypt.CompareHashAndPassword(hpw, pw)
	if err != nil {
		response := Response{
			Success: 0,
			Error:   err.Error(),
		}
		json.NewEncoder(w).Encode(response)
		return
	}

	//hash password
	hnpw, err := bcrypt.GenerateFromPassword(npw, 11)
	if !checkErr(err, w) {
		return
	}

	stmt, err := db.Prepare("UPDATE users SET password=? WHERE user_id=?")
	if !checkErr(err, w) {
		return
	}

	_, err = stmt.Exec(hnpw, user_id)
	if !checkErr(err, w) {
		return
	}

	response := Response{
		Success: 1,
	}
	json.NewEncoder(w).Encode(response)
}

func handleForgotPassword(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	if !checkKey(r.Form.Get("key"), w) {
		return
	}
	em := strings.ToLower(r.Form.Get("email"))
	if !validateEmail(em, w) {
		return
	}

	//new pass
	npw := randSeq(10)
	tnpw := hashSHA256(npw)
	hnpw, err := bcrypt.GenerateFromPassword([]byte(tnpw), 11)
	if !checkErr(err, w) {
		return
	}

	stmt, err := db.Prepare("UPDATE users SET password=? WHERE email=?")
	if !checkErr(err, w) {
		return
	}

	_, err = stmt.Exec(hnpw, em)
	if !checkErr(err, w) {
		return
	}

	//------BODY

	type SmtpTemplateData struct {
		From    string
		To      string
		Subject string
		Body    string
	}

	const emailTemplate = `From: {{.From}}
To: {{.To}}
Subject: {{.Subject}}

{{.Body}}

Sincerely,

{{.From}}
`

	var doc bytes.Buffer

	context := &SmtpTemplateData{
		"GameQ Support - No Reply",
		em,
		"Password Reset",
		"Your GameQ password has been reset for the account with this email address. Your new password is '" + npw + "'. You should change this password as soon as possible.",
	}
	t := template.New("emailTemplate")
	t, err = t.Parse(emailTemplate)
	if err != nil {
		log.Print("error trying to parse mail template")
	}
	err = t.Execute(&doc, context)
	if err != nil {
		log.Print("error trying to execute mail template")
	}

	//------END BODY

	auth := smtp.PlainAuth("", "gqform", "kaknaestorn1", "smtp.gmail.com")

	err = smtp.SendMail("smtp.gmail.com:587", auth, "gqform", []string{em}, doc.Bytes())
	if !checkErr(err, w) {
		return
	}

	response := Response{
		Success: 1,
	}
	json.NewEncoder(w).Encode(response)
}

func handleSubmitCSV(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	if !checkKey(r.Form.Get("key"), w) {
		return
	}
	di, err := strconv.ParseInt(r.Form.Get("device_id"), 10, 0)
	st := r.Form.Get("session_token")
	gm, err := strconv.ParseInt(r.Form.Get("game"), 10, 0)
	csv := r.Form.Get("csv")
	sys := strings.Split(r.URL.Path[1:], "/")[0]
	t, err := strconv.ParseInt(r.Form.Get("type"), 10, 0)

	//fmt.Fprintf(w, "di: %s, st: %s, gm: %s, sys: %s", di, st, gm, sys)

	//check session
	err, _ = checkSession(int(di), st, sys, w)
	if !checkErr(err, w) {
		return
	}
	p := fmt.Sprint("/home/ubuntu/CSVs/", t, "/", gm)
	ex, err := pathexists(p)
	if !checkErr(err, w) {
		return
	}
	if !ex {
		p2 := fmt.Sprint("/home/ubuntu/CSVs/", t)
		ex2, err := pathexists(p2)
		if !checkErr(err, w) {
			return
		}
		if !ex2 {
			err = os.Mkdir("/home/ubuntu/CSVs"+string(filepath.Separator)+strconv.FormatInt(t, 10), 0777)
			if !checkErr(err, w) {
				return
			}
		}

		err = os.Mkdir("/home/ubuntu/CSVs"+string(filepath.Separator)+strconv.FormatInt(t, 10)+string(filepath.Separator)+strconv.FormatInt(gm, 10), 0777)
		if !checkErr(err, w) {
			return
		}
	}

	d := []byte(csv)
	f := fmt.Sprint("/home/ubuntu/CSVs/", t, "/", gm, "/", di, "_", int32(time.Now().Unix()))
	err = ioutil.WriteFile(f, d, 0777)
	if !checkErr(err, w) {
		return
	}

	response := Response{
		Success: 1,
	}
	json.NewEncoder(w).Encode(response)

}

func handleSubmitFeedback(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	if !checkKey(r.Form.Get("key"), w) {
		return
	}
	di, err := strconv.ParseInt(r.Form.Get("device_id"), 10, 0)
	st := r.Form.Get("session_token")
	fb := r.Form.Get("feedback")
	sys := strings.Split(r.URL.Path[1:], "/")[0]

	//fmt.Fprintf(w, "di: %s, st: %s, gm: %s, sys: %s", di, st, gm, sys)

	//check session
	err, _ = checkSession(int(di), st, sys, w)
	if !checkErr(err, w) {
		return
	}

	d := []byte(fb)
	f := fmt.Sprint("/home/ubuntu/Feedback/", di, "_", int32(time.Now().Unix()))
	err = ioutil.WriteFile(f, d, 0777)
	if !checkErr(err, w) {
		return
	}

	response := Response{
		Success: 1,
	}
	json.NewEncoder(w).Encode(response)

}

// exists returns whether the given file or directory exists or not
func pathexists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return true, err
}

func hashSHA256(toHash string) string {
	d := []byte(toHash)
	hasher := sha256.New()
	hasher.Write(d)
	return hex.EncodeToString(hasher.Sum(nil))
}

func checkKey(k string, w http.ResponseWriter) (bol bool) {
	if k != "68440fe0484ad2bb1656b56d234ca5f463f723c3d3d58c3398190877d1d963bb" {
		response := Response{
			Success: 0,
			Error:   "Invalid Key",
		}
		json.NewEncoder(w).Encode(response)
		return false
	}
	return true
}

//crypto
/*
//hpw, err := bcrypt.GenerateFromPassword(pw, 11)
//if !checkErr(err, w) { return }

err = bcrypt.CompareHashAndPassword(hashedPassword, password)
if err == nil {
//match
} else {
//password mismatch
}
*/

//open conenction
/*
db, err := sql.Open("mysql", "basicuser:kokanonaesostotorornonetot1@tcp(gqdb.cljdjugbpchc.eu-west-1.rds.amazonaws.com:3306)/GQDB")
if !checkErr(err, w) { return }
*/

//close connection
/*
db.Close()
*/

// insert
/*
stmt, err := db.Prepare("INSERT userinfo SET username=?,departname=?,created=?")
if !checkErr(err, w) { return }

res, err := stmt.Exec("astaxie", "研发部门", "2012-12-09")
if !checkErr(err, w) { return }

id, err := res.LastInsertId()
if !checkErr(err, w) { return }

fmt.Println(id)
*/

// update
/*
stmt, err = db.Prepare("update userinfo set username=? where uid=?")
if !checkErr(err, w) { return }

res, err = stmt.Exec("astaxieupdate", id)
if !checkErr(err, w) { return }

affect, err := res.RowsAffected()
if !checkErr(err, w) { return }

fmt.Println(affect)
*/

// query
/*
rows, err := db.Query("SELECT * FROM userinfo")
if !checkErr(err, w) { return }

for rows.Next() {
var uid int
var username string
var department string
var created string
err = rows.Scan(&uid, &username, &department, &created)
if !checkErr(err, w) { return }
fmt.Println(uid)
fmt.Println(username)
fmt.Println(department)
fmt.Println(created)
}
*/

// delete
/*
stmt, err = db.Prepare("delete from userinfo where uid=?")
if !checkErr(err, w) { return }

res, err = stmt.Exec(id)
if !checkErr(err, w) { return }

affect, err = res.RowsAffected()
if !checkErr(err, w) { return }

fmt.Println(affect)
*/

var db *sql.DB
var myip string
var channels = make(map[int]chan string)

func DbConnect() *sql.DB {

	db, err := sql.Open("mysql", "basicuser:kokanonaesostotorornonetot1@tcp(gqdb.cljdjugbpchc.eu-west-1.rds.amazonaws.com:3306)/GQDB")
	if err != nil {
		return nil
	}
	return db

}

func main() {

	db = DbConnect()
	db.SetMaxIdleConns(1000)
	myip = getPublicIP()

	http.HandleFunc("/", handle404)
	http.HandleFunc("/computer/login", handleLogin)
	http.HandleFunc("/ios/login", handleLogin)
	http.HandleFunc("/android/login", handleLogin)
	http.HandleFunc("/computer/register", handleRegister)
	http.HandleFunc("/ios/register", handleRegister)
	http.HandleFunc("/android/register", handleRegister)
	http.HandleFunc("/computer/logout", handleLogout)
	http.HandleFunc("/ios/logout", handleLogout)
	http.HandleFunc("/android/logout", handleLogout)
	http.HandleFunc("/computer/setStatus", handleSetStatus)
	http.HandleFunc("/ios/getStatus", handleGetStatus)
	http.HandleFunc("/android/getStatus", handleGetStatus)
	http.HandleFunc("/android/updateToken", handleUpdateToken)
	http.HandleFunc("/ios/updateToken", handleUpdateToken)
	http.HandleFunc("/computer/versionControl", handleVersionControl)
	http.HandleFunc("/ios/versionControl", handleVersionControl)
	http.HandleFunc("/android/versionControl", handleVersionControl)
	http.HandleFunc("/computer/submitCSV", handleSubmitCSV)
	http.HandleFunc("/computer/submitFeedback", handleSubmitFeedback)
	http.HandleFunc("/ios/submitFeedback", handleSubmitFeedback)
	http.HandleFunc("/android/submitFeedback", handleSubmitFeedback)
	http.HandleFunc("/android/updatePassword", handleUpdatePassword)
	http.HandleFunc("/computer/updatePassword", handleUpdatePassword)
	http.HandleFunc("/ios/updateAutoAccept", handleUpdateAutoAccept)
	http.HandleFunc("/android/updateAutoAccept", handleUpdateAutoAccept)
	http.HandleFunc("/ios/getAutoAccept", handleGetAutoAccept)
	http.HandleFunc("/android/getAutoAccept", handleGetAutoAccept)
	http.HandleFunc("/ios/updatePassword", handleUpdatePassword)
	http.HandleFunc("/android/forgotPassword", handleForgotPassword)
	http.HandleFunc("/computer/forgotPassword", handleForgotPassword)
	http.HandleFunc("/ios/forgotPassword", handleForgotPassword)
	http.HandleFunc("/ios/accept", handleAccept)
	http.HandleFunc("/android/accept", handleAccept)

	http.HandleFunc("/test/push", handleTestPush)

	s := &http.Server{
		Addr:           ":8080",
		Handler:        nil,
		ReadTimeout:    60 * time.Second,
		WriteTimeout:   60 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}
	log.Fatal(s.ListenAndServe())

}

func getPublicIP() string {
	resp, err := http.Get("http://myexternalip.com/raw")
	if err != nil {
		os.Stderr.WriteString(err.Error())
		os.Stderr.WriteString("\n")
		os.Exit(1)
	}
	defer resp.Body.Close()
	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)
	s := buf.String()
	return s
}

func handleTestPush(w http.ResponseWriter, r *http.Request) {
	pushQueuePop(w, 1, 29, db, 1)

}
