package main

//TODO , threading
//TODO , prepare all statements
import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
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
	rows, err := stmtSelectCredentials.Query(em)
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
	_, err = stmtClearLoginAttempt.Exec(user_id, int32(time.Now().Unix()))
	if !checkErr(err, w) {
		return
	}
	//fmt.Fprintf(w, "pw:%s di:%s pt:%s sys:%s hpw:%s", pw, di, pt, sys, hpw)

	//check how many rows remain
	rows2, err2 := stmtGetLoginAttempts.Query(user_id)
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

		_, err = stmtInsertLoginAttempt.Exec(user_id, int32(time.Now().Unix()))
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

	if di == 0 {
		//insert new entry
		if sys == "computer" {
			//is computer

			_, err = stmtUpdateSession.Exec(nil, "", user_id)
			if !checkErr(err, w) {
				return
			}

			res, err := stmtInsertComputer.Exec(user_id, 0, 0, hst)
			if !checkErr(err, w) {
				return
			}
			di, err = res.LastInsertId()
			if !checkErr(err, w) {
				return
			}
		} else {
			var upMobileWithPT *sql.Stmt
			var insertMobile *sql.Stmt
			if sys == "android" {
				upMobileWithPT = stmtUpdateAndroidWithPT
				insertMobile = stmtInsertAndroid
			} else if sys == "ios" {
				upMobileWithPT = stmtUpdateIphoneWithPT
				insertMobile = stmtInsertIphone
			}
			_, err = upMobileWithPT.Exec(nil, "", "", pt)
			if !checkErr(err, w) {
				return
			}
			res, err := insertMobile.Exec(user_id, pt, hst)
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
		if sys == "computer" {
			//is computer
			//log out other computers

			_, err = stmtUpdateSession.Exec(nil, "", user_id)
			if !checkErr(err, w) {
				return
			}
			_, err = stmtUpdateComputer.Exec(user_id, 0, 0, hst, di)
			if !checkErr(err, w) {
				return
			}
		} else {
			var stmtUpdateMobile *sql.Stmt
			if sys == "android" {
				stmtUpdateMobile = stmtUpdateAndroid
			} else if sys == "ios" {
				stmtUpdateMobile = stmtUpdateIphone
			}

			_, err = stmtUpdateMobile.Exec(user_id, pt, hst, di)
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
	var stmtCheckSess *sql.Stmt
	if sys == "ios" {
		stmtCheckSess = stmtCheckIphoneSession
	} else if sys == "android" {
		stmtCheckSess = stmtCheckAndroidSession
	} else if sys == "computer" {
		stmtCheckSess = stmtCheckComputerSession
	}

	rows, err := stmtCheckSess.Query(di)
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
		//return err, u_id
		return errors.New("missing session"), u_id
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

	if sys == "computer" {

		_, err = stmtUpdateComputer.Exec(nil, 0, 0, "", di)
		if !checkErr(err, w) {
			return
		}
	} else {
		var stmtUpdateMobile *sql.Stmt
		if sys == "ios" {
			stmtUpdateMobile = stmtUpdateIphone
		} else if sys == "android" {
			stmtUpdateMobile = stmtUpdateAndroid
		}
		_, err = stmtUpdateMobile.Exec(nil, "", "", di)
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
	rows, err := stmtCheckEmailExists.Query(em)
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
	res1, err := stmtInsertUser.Exec(em, hpw)
	if !checkErr(err, w) {
		return
	}
	user_id, err := res1.LastInsertId()
	if !checkErr(err, w) {
		return
	}

	//update appropriate tables as if logging in and give appropriate response
	if di == 0 {
		//insert new entry
		if sys == "computer" {
			//is computer

			_, err = stmtUpdateSession.Exec(nil, "", user_id)
			if !checkErr(err, w) {
				return
			}

			res, err := stmtInsertComputer.Exec(user_id, 0, 0, hst)
			if !checkErr(err, w) {
				return
			}
			di, err = res.LastInsertId()
			if !checkErr(err, w) {
				return
			}
		} else {
			var upMobileWithPT *sql.Stmt
			var insertMobile *sql.Stmt
			if sys == "android" {
				upMobileWithPT = stmtUpdateAndroidWithPT
				insertMobile = stmtInsertAndroid
			} else if sys == "ios" {
				upMobileWithPT = stmtUpdateIphoneWithPT
				insertMobile = stmtInsertIphone
			}
			_, err = upMobileWithPT.Exec(nil, "", "", pt)
			if !checkErr(err, w) {
				return
			}
			res, err := insertMobile.Exec(user_id, pt, hst)
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
		if sys == "computer" {
			//is computer
			//log out other computers

			_, err = stmtUpdateSession.Exec(nil, "", user_id)
			if !checkErr(err, w) {
				return
			}
			_, err = stmtUpdateComputer.Exec(user_id, 0, 0, hst, di)
			if !checkErr(err, w) {
				return
			}
		} else {
			var stmtUpdateMobile *sql.Stmt
			if sys == "android" {
				stmtUpdateMobile = stmtUpdateAndroid
			} else if sys == "ios" {
				stmtUpdateMobile = stmtUpdateIphone
			}

			_, err = stmtUpdateMobile.Exec(user_id, pt, hst, di)
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

	_, err = stmtUpdateStatus.Exec(sa, gm, int32(time.Now().Unix()), di)
	if !checkErr(err, w) {
		return
	}

	if r.Form.Get("status") == "4" {

		rows, err := stmtSelectAutoAccept.Query(user_id)
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
		IP:      myip,
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

	rows, err := stmtSelectStatus.Query(user_id)
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

	var stmtUpdatePushTokenMobile *sql.Stmt
	if sys == "ios" {
		stmtUpdatePushTokenMobile = stmtUpdatePushTokenAndroid
	} else if sys == "android" {
		stmtUpdatePushTokenMobile = stmtUpdatePushTokenIphone
	}

	_, err = stmtUpdatePushTokenMobile.Exec(pt, di)
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

	_, err = stmtUpdateAutoAccept.Exec(aa, uid)
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

	rows, err := stmtSelectAutoAccept.Query(uid)
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
	var ha int
	switch {
	case g == 0:
		gamestring = "Matchmaking"
		ha = 0
		break
	case g == 1:
		gamestring = "Dota2"
		ab = int32(time.Now().Unix()) + 45
		maxwait = 45
		ha = 1
		break
	case g == 2:
		gamestring = "HoN"
		ha = 0
		break
	case g == 3:
		gamestring = "CS:GO"
		maxwait = 20
		ab = int32(time.Now().Unix()) + 20
		ha = 1
		break
	case g == 4:
		gamestring = "HotS"
		ha = 0
		break
	case g == 5:
		gamestring = "LoL"
		maxwait = 10
		ab = int32(time.Now().Unix()) + 10
		ha = 1
		break
	case g > 5 || g < 0:
		gamestring = "Matchmaking"
		ha = 0
		break
	}

	var msg string
	if aa != 0 && ha != 0 {
		msg = "Accepted " + gamestring + " queue on your behalf, get back quick!"
	} else {
		msg = gamestring + " queue ended!"
	}

	//push to all iPhones
	rows, err := stmtSelectPushTokensIphone.Query(user_id)
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
				go pushToIos(token, msg, ab)
			}

		}
	}

	//push to all Androids

	rows2, err := stmtSelectPushTokensAndroid.Query(user_id)
	if !checkErr(err, w) {
		return
	}
	for rows2.Next() {

		var token string
		err = rows2.Scan(&token)
		if !checkErr(err, w) {
			return
		}
		if utf8.RuneCountInString(token) > 10 {

			go pushToAndroid(token, msg)

		}

	}
	var aaS string

	if aa != 0 {
		aaS = "auto"
	} else {
		aaS = "nonauto "
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

func pushToIos(t string, pl string, ab int32) bool {
	//pushit ios
	payload := apns.NewPayload()
	payload.Alert = pl
	payload.Sound = "NotifCustom1.aif"

	pn := apns.NewPushNotification()
	pn.AddPayload(payload)
	pn.DeviceToken = t

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

	/*
	   alert, _ := pn.PayloadString()
	   fmt.Println("  Alert:", alert)
	   fmt.Println("Success:", resp.Success)
	   fmt.Println("  Error:", resp.Error)*/

	return true
}

func pushToAndroid(t string, pl string) bool {
	data := map[string]interface{}{"message": pl}
	msg := gcm.NewMessage(data, t)

	// Create a Sender to send the message.
	sender := &gcm.Sender{ApiKey: "AIzaSyC2NvDf3WUbz_ekl6nR2CcpucmTRNmtPcg"}

	// Send the message and receive the response after at most two retries.
	_, err := sender.Send(msg, 2)
	if err != nil {
		return false
	}
	return true
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

	rows, err := stmtSelectPassword.Query(user_id)
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
			//Error:   err.Error(),
			Error: "Old password invalid",
		}
		json.NewEncoder(w).Encode(response)
		return
	}

	//hash password
	hnpw, err := bcrypt.GenerateFromPassword(npw, 11)
	if !checkErr(err, w) {
		return
	}

	_, err = stmtUpdatePassword.Exec(hnpw, user_id)
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

	_, err = stmtUpdatePasswordWithEmail.Exec(hnpw, em)
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

var stmtUpdatePassword *sql.Stmt
var stmtSelectCredentials *sql.Stmt
var stmtClearLoginAttempt *sql.Stmt
var stmtGetLoginAttempts *sql.Stmt
var stmtInsertLoginAttempt *sql.Stmt
var stmtUpdateSession *sql.Stmt
var stmtInsertAndroid *sql.Stmt
var stmtInsertIphone *sql.Stmt
var stmtInsertComputer *sql.Stmt
var stmtUpdateComputer *sql.Stmt
var stmtUpdateIphone *sql.Stmt
var stmtUpdateAndroid *sql.Stmt
var stmtUpdateIphoneWithPT *sql.Stmt
var stmtUpdateAndroidWithPT *sql.Stmt
var stmtCheckComputerSession *sql.Stmt
var stmtCheckIphoneSession *sql.Stmt
var stmtCheckAndroidSession *sql.Stmt
var stmtCheckEmailExists *sql.Stmt
var stmtInsertUser *sql.Stmt
var stmtUpdateStatus *sql.Stmt
var stmtSelectAutoAccept *sql.Stmt
var stmtSelectStatus *sql.Stmt
var stmtUpdatePushTokenAndroid *sql.Stmt
var stmtUpdatePushTokenIphone *sql.Stmt
var stmtUpdateAutoAccept *sql.Stmt
var stmtSelectPushTokensIphone *sql.Stmt
var stmtSelectPushTokensAndroid *sql.Stmt
var stmtSelectPassword *sql.Stmt
var stmtUpdatePasswordWithEmail *sql.Stmt

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
	var err error
	stmtUpdatePassword, err = db.Prepare("UPDATE users SET password=? WHERE user_id=?")
	if err != nil {
		panic(err.Error())
	}
	stmtSelectCredentials, err = db.Prepare("SELECT user_id, password FROM users WHERE email=? LIMIT 1")
	if err != nil {
		panic(err.Error())
	}
	stmtClearLoginAttempt, err = db.Prepare("delete from login_attempts where user_id=? and ?-time>600")
	if err != nil {
		panic(err.Error())
	}
	stmtGetLoginAttempts, err = db.Prepare("SELECT * FROM login_attempts WHERE user_id=?")
	if err != nil {
		panic(err.Error())
	}
	stmtInsertLoginAttempt, err = db.Prepare("INSERT login_attempts SET user_id=?,time=?")
	if err != nil {
		panic(err.Error())
	}
	stmtUpdateSession, err = db.Prepare("update computers set user_id=?, session_token=? where user_id=?")
	if err != nil {
		panic(err.Error())
	}
	stmtInsertAndroid, err = db.Prepare("INSERT androids SET user_id=?, push_token=?, session_token=?")
	if err != nil {
		panic(err.Error())
	}
	stmtInsertIphone, err = db.Prepare("INSERT iphones SET user_id=?, push_token=?, session_token=?")
	if err != nil {
		panic(err.Error())
	}
	stmtInsertComputer, err = db.Prepare("INSERT computers SET user_id=?,status=?,game=?,session_token=?")
	if err != nil {
		panic(err.Error())
	}
	stmtUpdateComputer, err = db.Prepare("UPDATE computer SET user_id=?,status=?,game=?,session_token=? WHERE device_id=?")
	if err != nil {
		panic(err.Error())
	}
	stmtUpdateAndroid, err = db.Prepare("UPDATE androids SET user_id=?,push_token=?,session_token=? WHERE device_id=?")
	if err != nil {
		panic(err.Error())
	}
	stmtUpdateIphone, err = db.Prepare("UPDATE iphones SET user_id=?,push_token=?,session_token=? WHERE device_id=?")
	if err != nil {
		panic(err.Error())
	}
	stmtUpdateAndroidWithPT, err = db.Prepare("update androids set user_id=?, push_token=?, session_token=? where push_token=?")
	if err != nil {
		panic(err.Error())
	}
	stmtUpdateIphoneWithPT, err = db.Prepare("update iphones set user_id=?, push_token=?, session_token=? where push_token=?")
	if err != nil {
		panic(err.Error())
	}
	stmtCheckAndroidSession, err = db.Prepare("SELECT session_token, user_id FROM androids WHERE device_id=?")
	if err != nil {
		panic(err.Error())
	}
	stmtCheckIphoneSession, err = db.Prepare("SELECT session_token, user_id FROM iphones WHERE device_id=?")
	if err != nil {
		panic(err.Error())
	}
	stmtCheckComputerSession, err = db.Prepare("SELECT session_token, user_id FROM computers WHERE device_id=?")
	if err != nil {
		panic(err.Error())
	}
	stmtCheckEmailExists, err = db.Prepare("SELECT * FROM users WHERE email=? LIMIT 1")
	if err != nil {
		panic(err.Error())
	}
	stmtInsertUser, err = db.Prepare("INSERT users SET email=?,password=?")
	if err != nil {
		panic(err.Error())
	}
	stmtUpdateStatus, err = db.Prepare("update computers set status=?, game=?, status_timestamp=?, status_ip=INET_ATON('" + myip + "') where device_id=?")
	if err != nil {
		panic(err.Error())
	}
	stmtSelectAutoAccept, err = db.Prepare("SELECT auto_accept FROM users WHERE user_id=? LIMIT 1")
	if err != nil {
		panic(err.Error())
	}
	stmtSelectStatus, err = db.Prepare("SELECT game, status, status_timestamp, INET_NTOA(`status_ip`) FROM computers WHERE user_id=? LIMIT 1")
	if err != nil {
		panic(err.Error())
	}
	stmtUpdatePushTokenAndroid, err = db.Prepare("update androids set push_token=? where device_id=?")
	if err != nil {
		panic(err.Error())
	}
	stmtUpdatePushTokenIphone, err = db.Prepare("update iphones set push_token=? where device_id=?")
	if err != nil {
		panic(err.Error())
	}
	stmtUpdateAutoAccept, err = db.Prepare("update users set auto_accept=? where user_id=?")
	if err != nil {
		panic(err.Error())
	}
	stmtSelectPushTokensIphone, err = db.Prepare("SELECT push_token FROM iphones WHERE user_id=?")
	if err != nil {
		panic(err.Error())
	}
	stmtSelectPushTokensAndroid, err = db.Prepare("SELECT push_token FROM androids WHERE user_id=?")
	if err != nil {
		panic(err.Error())
	}
	stmtSelectPassword, err = db.Prepare("SELECT password FROM users WHERE user_id=? LIMIT 1")
	if err != nil {
		panic(err.Error())
	}
	stmtUpdatePasswordWithEmail, err = db.Prepare("UPDATE users SET password=? WHERE email=?")
	if err != nil {
		panic(err.Error())
	}

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
	s := strings.TrimSpace(buf.String())
	return s
}

func handleTestPush(w http.ResponseWriter, r *http.Request) {
	pushQueuePop(w, 1, 29, db, 1)

}
