package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/alexjlockwood/gcm"
	apns "github.com/anachronistic/apns"
	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
	"log"
	"math/rand"
	"net/http"
	"strings"
	"time"
)

func handle404(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "(404) Hi there, I love %s! Unfortunately, I couldn't find it :/", r.URL.Path[1:])
}

type Response struct {
	Success         int      `json:"succcess"`
	Error           string   `json:"error,omitempty"`
	Device_id       int      `json:"device_id,omitempty"`
	Session_token   string   `json:"session_token,omitempty"`
	Current_version string   `json:"current_version,omitempty"`
	Download_link   string   `json:"download_link,omitempty"`
	Statuses        []Status `json:"statuses,omitempty"`
}

type Status struct {
	Game   int `json:"game"`
	Status int `json:"status"`
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

	r.ParseForm()
	em := r.Form.Get("email")
	pw := []byte(r.Form.Get("password"))
	di := r.Form.Get("device_id")  //optional
	pt := r.Form.Get("push_token") //only mobile
	sys := strings.Split(r.URL.Path[1:], "/")[0]
	//fmt.Fprintf(w, "user: %s, pwd: %s, di: %s, pt: %s, sys: %s", em, pw, di, pt, sys)

	// connect to DB
	db, err := sql.Open("GQDB", "basicuser:kokanonaesostotorornonetot1@gqdb.cljdjugbpchc.eu-west-1.rds.amazonaws.com")
	chechErr(err, w)
	defer db.Close()

	//check email exists in users
	rows, err := db.Query("SELECT user_id, password FROM users WHERE email=? LIMIT 1")
	chechErr(err, w)
	n := 0
	var user_id int
	var password string
	for rows.Next() {
		n++
		err = rows.Scan(&user_id, &password)
	}
	if n == 0 {
		response := Response{
			Success: 0,
			Error:   "Invalid email address",
		}
		json.NewEncoder(w).Encode(response)
		return
	}

	//bruteforce check
	//first clear old rows
	stmt, err = db.Prepare("delete from login_attempts where user_id=? and ?-time<600")
	chechErr(err, w)
	res, err = stmt.Exec(user_id, int32(time.Now().Unix()))
	chechErr(err, w)

	//check how many rows remain
	rows2, err2 := db.Query("SELECT * FROM login_attempts WHERE user_id=?")
	checkErr(err2)
	n2 := 0
	for rows2.Next() {
		n2++
	}
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

	//check password
	erro := bcrypt.CompareHashAndPassword(hashedPassword, password)
	if erro != nil {
		//password mismatch
		//insert entry in login_attempts
		stmt, err := db.Prepare("INSERT login_attempts SET user_id=?,time=?")
		chechErr(err, w)
		res, err := stmt.Exec(user_id, int32(time.Now().Unix()))
		chechErr(err, w)

		//return error
		response := Response{
			Success: 0,
			Error:   "Invalid password",
		}
		json.NewEncoder(w).Encode(response)
		return
	}

	//login info valid
	//clear bruteforce
	stmt, err = db.Prepare("delete from login_attempts where user_id=?")
	chechErr(err, w)
	res, err = stmt.Exec(user_id)
	chechErr(err, w)

	//generate st
	st := randSeq(32)
	hst, err := bcrypt.GenerateFromPassword(st, 11)
	chechErr(err, w)

	//update appropriate tables and give appropriate response
	table := ""
	if sys == "ios" {
		table = "iphones"
	} else if sys == "android" {
		table = "androids"
	} else if sys == computer {
		table = "computers"
	}
	var buffer bytes.Buffer

	if di == 0 {
		//insert new entry
		buffer.WriteString("INSERT ")
		buffer.WriteString(table)
		if sys == "computer" {
			//is computer
			buffer.WriteString(" SET user_id=?,status=?,game=?,q_time=?,session_token=?")
			stmt, err := db.Prepare(buffer.String())
			chechErr(err, w)
			res, err := stmt.Exec(user_id, 0, 0, 0, hst)
			chechErr(err, w)
			di, err := res.LastInsertId()
			chechErr(err, w)
		} else {
			//is mobile, insert push token
			buffer.WriteString(" SET user_id=?,push_token=?,session_token=?")
			stmt, err := db.Prepare(buffer.String())
			chechErr(err, w)
			res, err := stmt.Exec(user_id, pt, hst)
			chechErr(err, w)
			di, err := res.LastInsertId()
			chechErr(err, w)
		}
		// return device id, session token and success
		response := Response{
			Success:       1,
			Device_id:     di,
			Session_Token: st,
		}
		json.NewEncoder(w).Encode(response)

	} else {
		//device has entry already, update existing
		buffer.WriteString("UPDATE ")
		buffer.WriteString(table)
		if sys == "computer" {
			//is computer
			buffer.WriteString(" SET user_id=?,status=?,game=?,q_time=?,session_token=? WHERE device_id=?")
			stmt, err := db.Prepare(buffer.String())
			chechErr(err, w)
			res, err := stmt.Exec(user_id, 0, 0, 0, hst, di)
			chechErr(err, w)
		} else {
			//is mobile, insert push token
			buffer.WriteString(" SET user_id=?,push_token=?,session_token=? WHERE device_id=?")
			stmt, err := db.Prepare(buffer.String())
			chechErr(err, w)
			res, err := stmt.Exec(user_id, pt, hst, di)
			chechErr(err, w)
		}
		// return device id, session token and success
		response := Response{
			Success:       1,
			Session_Token: st,
		}
		json.NewEncoder(w).Encode(response)
	}

	//returned Optional(device_id), success, Optional(error), session_token
}

func checkSession(di string, st string, sys string) (err error, uid string) {
	db, err := sql.Open("GQDB", "basicuser:kokanonaesostotorornonetot1@gqdb.cljdjugbpchc.eu-west-1.rds.amazonaws.com")
	defer db.Close()
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
	checkErr(err)

	var hst string
	var u_id int
	for rows.Next() {
		err = rows.Scan(&hst, &u_id)
		checkErr(err)

	}
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
	di := r.Form.Get("device_id")
	st := r.Form.Get("session_token")
	sys := strings.Split(r.URL.Path[1:], "/")[0]
	err := checkSession(di, st, sys)
	checkErr(err, w)
	//fmt.Fprintf(w, "di: %s, st: %s, sys: %s", di, st, sys)
	var buffer bytes.Buffer
	db, err := sql.Open("GQDB", "basicuser:kokanonaesostotorornonetot1@gqdb.cljdjugbpchc.eu-west-1.rds.amazonaws.com")
	defer db.Close()
	buffer.WriteString("UPDATE ")
	if sys == "computer" {
		buffer.WriteString("computers")
	} else if sys == "ios" {
		buffer.WriteString("iphones")
	} else if sys == "android" {
		buffer.WriteString("androids")
	}
	if sys == "computer" {
		buffer.WriteString(" SET user_id=?, session_token=?, status=?, game=?, q_time=? WHERE device_id=?")
		stmt, err := db.Prepare(buffer.String())
		chechErr(err, w)
		res, err := stmt.Exec(nil, "", 0, 0, 0, di)
		chechErr(err, w)
	} else {
		buffer.WriteString(" SET user_id=?, session_token=?, push_token=? WHERE device_id=?")
		stmt, err := db.Prepare(buffer.String())
		chechErr(err, w)
		res, err := stmt.Exec(nil, "", "", di)
		chechErr(err, w)
	}
	response := Response{
		Success: 1,
	}
	json.NewEncoder(w).Encode(response)
	//returned success
}

func handleRegister(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	em := r.Form.Get("email")
	pw := []byte(r.Form.Get("password"))
	di := r.Form.Get("device_id")  //optional
	pt := r.Form.Get("push_token") //only mobile
	sys := strings.Split(r.URL.Path[1:], "/")[0]
	//fmt.Fprintf(w, "user: %s, pwd: %s, di: %s, pt: %s, sys: %s", em, pw, di, pt, sys)

	// connect to DB
	db, err := sql.Open("GQDB", "basicuser:kokanonaesostotorornonetot1@gqdb.cljdjugbpchc.eu-west-1.rds.amazonaws.com")
	chechErr(err, w)
	defer db.Close()

	//check email exists in users
	rows, err := db.Query("SELECT * FROM users WHERE email=? LIMIT 1")
	chechErr(err, w)
	n := 0
	var user_id int
	var password string
	for rows.Next() {
		n++
		break
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
	checkErr(err)

	//proceed with registration

	//generate st and hst
	st := randSeq(32)
	hst, err := bcrypt.GenerateFromPassword(st, 11)
	chechErr(err, w)

	//insert entry to users
	stmt, err := db.Prepare("INSERT users SET email=?,password=?")
	checkErr(err, w)
	res1, err := stmt.Exec(em, hpw)
	checkErr(err, w)
	user_id, err := res1.LastInsertId()
	chechErr(err, w)

	//update appropriate tables as if logging in and give appropriate response
	table := ""
	if sys == "ios" {
		table = "iphones"
	} else if sys == "android" {
		table = "androids"
	} else if sys == computer {
		table = "computers"
	}
	var buffer bytes.Buffer

	if di == 0 {
		//insert new entry
		buffer.WriteString("INSERT ")
		buffer.WriteString(table)
		if sys == "computer" {
			//is computer
			buffer.WriteString(" SET user_id=?,status=?,game=?,q_time=?,session_token=?")
			stmt, err := db.Prepare(buffer.String())
			chechErr(err, w)
			res, err := stmt.Exec(user_id, 0, 0, 0, hst)
			chechErr(err, w)
			di, err := res.LastInsertId()
			chechErr(err, w)
		} else {
			//is mobile, insert push token
			buffer.WriteString(" SET user_id=?,push_token=?,session_token=?")
			stmt, err := db.Prepare(buffer.String())
			chechErr(err, w)
			res, err := stmt.Exec(user_id, pt, hst)
			chechErr(err, w)
			di, err := res.LastInsertId()
			chechErr(err, w)
		}
		// return device id, session token and success
		response := Response{
			Success:       1,
			Device_id:     di,
			Session_Token: st,
		}
		json.NewEncoder(w).Encode(response)

	} else {
		//device has entry already, update existing
		buffer.WriteString("UPDATE ")
		buffer.WriteString(table)
		if sys == "computer" {
			//is computer
			buffer.WriteString(" SET user_id=?,status=?,game=?,q_time=?,session_token=? WHERE device_id=?")
			stmt, err := db.Prepare(buffer.String())
			chechErr(err, w)
			res, err := stmt.Exec(user_id, 0, 0, 0, hst, di)
			chechErr(err, w)
		} else {
			//is mobile, insert push token
			buffer.WriteString(" SET user_id=?,push_token=?,session_token=? WHERE device_id=?")
			stmt, err := db.Prepare(buffer.String())
			chechErr(err, w)
			res, err := stmt.Exec(user_id, pt, hst, di)
			chechErr(err, w)
		}
		// return device id, session token and success
		response := Response{
			Success:       1,
			Session_Token: st,
		}
		json.NewEncoder(w).Encode(response)
	}
	//returned Optional(device_id), success, Optional(error), session_token
}

func handleSetStatus(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	sa := r.Form.Get("status")
	st := r.Form.Get("session_token")
	di := r.Form.Get("device_id")
	gm := r.Form.Get("game") //optional
	sys := strings.Split(r.URL.Path[1:], "/")[0]

	//fmt.Fprintf(w, "status: %s, st: %s, di: %s, gm: %s", sa, st, di, gm)
	db, err := sql.Open("GQDB", "basicuser:kokanonaesostotorornonetot1@gqdb.cljdjugbpchc.eu-west-1.rds.amazonaws.com")
	checkErr(err)
	defer db.Close()

	//check session
	err, user_id := checkSession(di, st, sys)
	checkErr(err)

	//update status
	stmt, err = db.Prepare("update computers set status=?, game=? where device_id=?")
	checkErr(err)

	res, err = stmt.Exec(sa, gm)
	checkErr(err)
	response := Response{
		Success: 1,
	}
	json.NewEncoder(w).Encode(response)
	//return success, Optional(error)

}

func handleGetStatus(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	di := r.Form.Get("device_id")
	st := r.Form.Get("session_token")
	sys := strings.Split(r.URL.Path[1:], "/")[0]
	//fmt.Fprintf(w, "di: %s, st: %s, sys: %s", di, st, sys)

	db, err := sql.Open("GQDB", "basicuser:kokanonaesostotorornonetot1@gqdb.cljdjugbpchc.eu-west-1.rds.amazonaws.com")
	checkErr(err)
	defer db.Close()

	//check session
	err, user_id := checkSession(di, st, sys)
	checkErr(err)

	rows, err := db.Query("SELECT game, status FROM computers WHERE user_id=?", user_id)
	checkErr(err)
	n := 0

	var statuses []Status
	for rows.Next() {

		var status int
		var game int
		err = rows.Scan(&game, &status)
		checkErr(err)
		statstruct := Status{
			Game:   game,
			Status: status,
		}
		statuses = append(statuses, statstruct)
	}

	response := Response{
		Success:  1,
		Statuses: statuses,
	}
	json.NewEncoder(w).Encode(response)

	//return success, Optional(error), status, Optional(game)
}

func handleUpdateToken(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	st := r.Form.Get("session_token")
	di := r.Form.Get("device_id")
	pt := r.Form.Get("push_token")
	sys := strings.Split(r.URL.Path[1:], "/")[0]
	//fmt.Fprintf(w, "st: %s, di: %s, pt: %s, sys: %s", st, di, pt, sys)
	db, err := sql.Open("GQDB", "basicuser:kokanonaesostotorornonetot1@gqdb.cljdjugbpchc.eu-west-1.rds.amazonaws.com")
	checkErr(err)
	defer db.Close()

	//check session
	err, user_id := checkSession(di, st, sys)
	checkErr(err)

	var table string

	if sys == "ios" {
		table = "iphones"
	} else if sys == "android" {
		table = "androids"
	}

	stmt, err = db.Prepare("update " + table + " set push_token=? where device_id=?")
	checkErr(err)

	res, err = stmt.Exec(pt, di)
	checkErr(err)

	response := Response{
		Success: 1,
	}
	json.NewEncoder(w).Encode(response)

	//returned success, Optional(error)
}

func handlePush(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	di := r.Form.Get("device_id")
	st := r.Form.Get("session_token")
	gm := r.Form.Get("game")
	ab := r.Form.Get("accept_before")
	sys := strings.Split(r.URL.Path[1:], "/")[0]

	//fmt.Fprintf(w, "di: %s, st: %s, gm: %s, sys: %s", di, st, gm, sys)

	db, err := sql.Open("GQDB", "basicuser:kokanonaesostotorornonetot1@gqdb.cljdjugbpchc.eu-west-1.rds.amazonaws.com")
	checkErr(err)
	defer db.Close()

	//check session
	err, user_id := checkSession(di, st, sys)
	checkErr(err)

	//pusb to all iPhones
	rows, err := db.Query("SELECT push_tokens FROM iphones WHERE user_id=?", user_id)
	checkErr(err)
	for rows.Next() {
		var token string
		err = rows.Scan(&token)
		checkErr(err)

		//pushit ios
		payload := apns.NewPayload()
		payload.Alert = "Queue ended for " + gameString + "!"
		payload.Sound = "queuepop.aiff"

		pn := apns.NewPushNotification()
		pn.AddPayload(payload)
		pn.DeviceToken = token

		pn.Set("accept_before", ab)

		client := apns.NewClient("TODO_SET_FOR_PRODUCTION/DEVELOPMENT_gateway.sandbox.push.apple.com:2195", "TODO_INSERT_YOUR_CERT_PEM", "TODO_INSERT_YOUR_KEY_NOENC_PEM")
		resp := client.Send(pn)
		/*
		   alert, _ := pn.PayloadString()
		   fmt.Println("  Alert:", alert)
		   fmt.Println("Success:", resp.Success)
		   fmt.Println("  Error:", resp.Error)*/

	}

	//push to all Androids
	rows2, err := db.Query("SELECT push_tokens FROM androids WHERE user_id=?", user_id)
	checkErr(err)
	for rows2.Next() {
		var token string
		err = rows.Scan(&token)
		checkErr(err)

		data := map[string]interface{}{"message": "Queue ended for " + gameString + "!"}
		regIDs := []string{token}
		msg := gcm.NewMessage(data, regIDs)

		// Create a Sender to send the message.
		sender := &gcm.Sender{ApiKey: "TODO_INSERT_GCM_KEY"}

		// Send the message and receive the response after at most two retries.
		response, err := sender.Send(msg, 2)
		if err != nil {
			response := Response{
				Success: 0,
				Error:   "Failed to send message:" + err,
			}
			json.NewEncoder(w).Encode(response)
			return
		}

	}

	response := Response{
		Success: 1,
	}
	json.NewEncoder(w).Encode(response)

	//return success, Optional(error)
}

func handleVersionControl(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
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

func checkErr(err error, w http.ResponseWriter) {
	if err != nil {
		response := Response{
			Success: 0,
			Error:   err,
		}
		json.NewEncoder(w).Encode(response)
		panic()
	}
}

//crypto
/*
//hpw, err := bcrypt.GenerateFromPassword(pw, 11)
//checkErr(err)

err = bcrypt.CompareHashAndPassword(hashedPassword, password)
if err == nil {
//match
} else {
//password mismatch
}
*/

//open conenction
/*
db, err := sql.Open("GQDB", "basicuser:kokanonaesostotorornonetot1@gqdb.cljdjugbpchc.eu-west-1.rds.amazonaws.com")
checkErr(err)
*/

//close connection
/*
db.Close()
*/

// insert
/*
stmt, err := db.Prepare("INSERT userinfo SET username=?,departname=?,created=?")
checkErr(err)

res, err := stmt.Exec("astaxie", "研发部门", "2012-12-09")
checkErr(err)

id, err := res.LastInsertId()
checkErr(err)

fmt.Println(id)
*/

// update
/*
stmt, err = db.Prepare("update userinfo set username=? where uid=?")
checkErr(err)

res, err = stmt.Exec("astaxieupdate", id)
checkErr(err)

affect, err := res.RowsAffected()
checkErr(err)

fmt.Println(affect)
*/

// query
/*
rows, err := db.Query("SELECT * FROM userinfo")
checkErr(err)

for rows.Next() {
var uid int
var username string
var department string
var created string
err = rows.Scan(&uid, &username, &department, &created)
checkErr(err)
fmt.Println(uid)
fmt.Println(username)
fmt.Println(department)
fmt.Println(created)
}
*/

// delete
/*
stmt, err = db.Prepare("delete from userinfo where uid=?")
checkErr(err)

res, err = stmt.Exec(id)
checkErr(err)

affect, err = res.RowsAffected()
checkErr(err)

fmt.Println(affect)
*/

func main() {

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
	http.HandleFunc("/computer/updateToken", handleUpdateToken)
	http.HandleFunc("/ios/updateToken", handleUpdateToken)
	http.HandleFunc("/android/push", handlePush)
	http.HandleFunc("/computer/versionControl", handleVersionControl)
	http.HandleFunc("/ios/versionControl", handleVersionControl)
	http.HandleFunc("/android/versionControl", handleVersionControl)

	s := &http.Server{
		Addr:           ":8080",
		Handler:        nil,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}
	log.Fatal(s.ListenAndServe())

}
