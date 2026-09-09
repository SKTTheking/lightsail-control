package main

import (
	"bytes"
	"encoding/json"
	"github.com/google/uuid"
	"github.com/komari-monitor/komari/database/dbcore"
	"github.com/komari-monitor/komari/database/models"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

var testApp *App

func TestMain(m *testing.M) {
	dir, e := os.MkdirTemp("", "lc-go-tests-")
	if e != nil {
		panic(e)
	}
	if e = os.Chdir(dir); e != nil {
		panic(e)
	}
	db, e := initDB()
	if e != nil {
		panic(e)
	}
	testApp = &App{DB: db, Origin: "https://control.example", Secure: true, Attempts: map[string][]int64{}}
	result := m.Run()
	dbcore.Close()
	os.RemoveAll(dir)
	os.Exit(result)
}
func request(method, path string, data any, auth string, admin bool, csrf bool) *httptest.ResponseRecorder {
	b, _ := json.Marshal(data)
	r := httptest.NewRequest(method, path, bytes.NewReader(b))
	r.Header.Set("Content-Type", "application/json")
	if auth != "" {
		r.Header.Set("Authorization", "Bearer "+auth)
	}
	if admin {
		r.AddCookie(&http.Cookie{Name: "lc_session", Value: "admin-test"})
	}
	if csrf {
		r.Header.Set("Origin", testApp.Origin)
		r.Header.Set("X-CSRF-Token", "csrf-test")
	}
	w := httptest.NewRecorder()
	testApp.router().ServeHTTP(w, r)
	return w
}
func adminSession(t *testing.T) {
	t.Helper()
	s := LoginSession{Hash: digest("admin-test"), CSRF: "csrf-test", Expires: time.Now().Unix() + 300}
	if e := testApp.DB.Save(&s).Error; e != nil {
		t.Fatal(e)
	}
}
func fixtureNode(t *testing.T, credential string) Node {
	t.Helper()
	id := uuid.NewString()
	if e := testApp.DB.Create(&models.Client{UUID: id, Name: id, Token: digest(token())}).Error; e != nil {
		t.Fatal(e)
	}
	n := Node{ID: id, Name: "node", TokenHash: digest(credential), LastSeen: time.Now().Unix(), Quota: 1e12}
	if e := testApp.DB.Create(&n).Error; e != nil {
		t.Fatal(e)
	}
	return n
}

func TestDeleteNodeInvalidatesCredentialsAndKeepsHistory(t *testing.T) {
	adminSession(t)
	n := fixtureNode(t, "delete-agent")
	other := fixtureNode(t, "keep-agent")
	testApp.DB.Model(&n).Updates(map[string]any{"enroll_hash": digest("delete-enrollment"), "enroll_expires": time.Now().Unix() + 900})
	j := Job{ID: uuid.NewString(), NodeID: n.ID, State: "running", Logs: "preserved"}
	if err := testApp.DB.Create(&j).Error; err != nil {
		t.Fatal(err)
	}
	path := "/api/nodes/" + n.ID + "/delete"
	for _, tc := range []struct {
		admin, csrf bool
		code        int
	}{{false, false, 401}, {true, false, 403}, {true, true, 200}} {
		if w := request("POST", path, map[string]any{}, "", tc.admin, tc.csrf); w.Code != tc.code {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	var count int64
	testApp.DB.Model(&Node{}).Where("id = ?", n.ID).Count(&count)
	if count != 0 {
		t.Fatal("node still exists")
	}
	testApp.DB.Model(&models.Client{}).Where("uuid = ?", n.ID).Count(&count)
	if count != 0 {
		t.Fatal("Komari client still exists")
	}
	if err := testApp.DB.First(&j, "id = ?", j.ID).Error; err != nil {
		t.Fatal(err)
	}
	if j.State != "revoked" || !j.Cancel || j.Logs != "preserved" {
		t.Fatal(j)
	}
	if w := request("POST", "/agent/poll", map[string]any{}, "delete-agent", false, false); w.Code != 401 {
		t.Fatal("deleted agent accepted")
	}
	if w := request("POST", "/enroll", nil, "delete-enrollment", false, false); w.Code != 401 {
		t.Fatal("deleted enrollment accepted")
	}
	if w := request("POST", path, map[string]any{}, "", true, true); w.Code != 404 {
		t.Fatal("missing node accepted")
	}
	if err := testApp.DB.First(&Node{}, "id = ?", other.ID).Error; err != nil {
		t.Fatal("other node affected", err)
	}
	testApp.DB.Model(&Audit{}).Where("action = ? AND target = ?", "node_deleted", n.ID+":"+n.Name).Count(&count)
	if count != 1 {
		t.Fatal("missing deletion audit")
	}
}

func TestAuthenticationAndCSRF(t *testing.T) {
	adminSession(t)
	for _, path := range []string{"/api/nodes", "/api/jobs", "/api/audit"} {
		if w := request("GET", path, nil, "", false, false); w.Code != 401 {
			t.Fatalf("%s: %d", path, w.Code)
		}
	}
	if w := request("POST", "/api/nodes", map[string]any{"name": "a"}, "", true, false); w.Code != 403 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := request("POST", "/api/nodes", map[string]any{"name": "a"}, "", true, true); w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	for _, path := range []string{"/api/rpc2", "/api/admin/plugin/list", "/api/admin/task/exec"} {
		if w := request("GET", path, nil, "", true, true); w.Code != 404 {
			t.Fatal(path, w.Code)
		}
	}
}
func TestAgentIsolationAndNoReplay(t *testing.T) {
	adminSession(t)
	a := fixtureNode(t, "a")
	b := fixtureNode(t, "b")
	w := request("POST", "/api/jobs", map[string]any{"node_id": a.ID, "script": "echo hello", "title": "check", "timeout": 60}, "", true, true)
	if w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	var j Job
	json.Unmarshal(w.Body.Bytes(), &j)
	if w = request("POST", "/api/jobs", map[string]any{"node_id": a.ID, "script": "echo again", "timeout": 60}, "", true, true); w.Code != 409 {
		t.Fatal("duplicate active job", w.Code)
	}
	if w = request("POST", "/agent/poll", map[string]any{}, "b", false, false); !bytes.Contains(w.Body.Bytes(), []byte(`"job":null`)) {
		t.Fatal("wrong node received job", b.ID)
	}
	if w = request("POST", "/agent/jobs/"+j.ID+"/events", Event{Seq: 1, State: "running"}, "b", false, false); w.Code != 404 {
		t.Fatal("cross node mutation", w.Code)
	}
	w = request("POST", "/agent/poll", map[string]any{}, "a", false, false)
	if !bytes.Contains(w.Body.Bytes(), []byte("echo hello")) {
		t.Fatal(w.Body.String())
	}
	w = request("POST", "/agent/poll", map[string]any{}, "a", false, false)
	if !bytes.Contains(w.Body.Bytes(), []byte(`"job":null`)) {
		t.Fatal("replayed claim")
	}
	w = request("GET", "/api/nodes", nil, "a", false, false)
	if w.Code != 401 {
		t.Fatal("agent became admin")
	}
}
func TestCompletionRequiresExitCodeAndDeduplicates(t *testing.T) {
	n := fixtureNode(t, "c")
	j := Job{ID: uuid.NewString(), NodeID: n.ID, State: "claimed", Created: time.Now().Unix(), Links: "[]"}
	testApp.DB.Create(&j)
	endpoint := "/agent/jobs/" + j.ID + "/events"
	if w := request("POST", endpoint, Event{Seq: 1, State: "succeeded"}, "c", false, false); w.Code != 400 {
		t.Fatal("accepted false success")
	}
	p := 100
	e := Event{Seq: 1, State: "running", Progress: &p, Log: "once\n"}
	for i := 0; i < 2; i++ {
		if w := request("POST", endpoint, e, "c", false, false); w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	testApp.DB.First(&j, "id = ?", j.ID)
	if j.Logs != "once\n" || j.Progress != 99 {
		t.Fatal("log duplicate or premature 100%", j)
	}
	if w := request("POST", endpoint, Event{Seq: 2, State: "running", Links: []string{"javascript:alert(1)"}}, "c", false, false); w.Code != 400 {
		t.Fatal("active content link allowed")
	}
	zero := 0
	if w := request("POST", endpoint, Event{Seq: 2, State: "succeeded", ExitCode: &zero}, "c", false, false); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	testApp.DB.First(&j, "id = ?", j.ID)
	if j.State != "succeeded" || j.Progress != 100 {
		t.Fatal(j)
	}
}
func TestEnrollmentSingleUseAndSmallBootstrap(t *testing.T) {
	adminSession(t)
	n := fixtureNode(t, "d")
	w := request("POST", "/api/nodes/"+n.ID+"/enrollment", map[string]any{}, "", true, true)
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	var r struct {
		Script string `json:"script"`
	}
	json.Unmarshal(w.Body.Bytes(), &r)
	if len(r.Script) >= 16*1024 {
		t.Fatal("AWS user-data limit exceeded")
	}
	secret := "enrollment"
	testApp.DB.Model(&n).Updates(map[string]any{"enroll_hash": digest(secret), "enroll_expires": time.Now().Unix() + 60})
	if w = request("POST", "/enroll", nil, secret, false, false); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w = request("POST", "/enroll", nil, secret, false, false); w.Code != 401 {
		t.Fatal("enrollment reused")
	}
	if w = request("GET", "/agent/code", nil, "d", false, false); w.Code != 401 {
		t.Fatal("old credential accepted after enrollment")
	}
}
