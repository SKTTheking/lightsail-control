// Lightsail Control: a restricted application built on Komari's database,
// server records and metric store. The upstream router/plugin engine is not mounted.
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/komari-monitor/komari/cmd/flags"
	"github.com/komari-monitor/komari/database/clients"
	"github.com/komari-monitor/komari/database/dbcore"
	"github.com/komari-monitor/komari/database/models"
	"github.com/komari-monitor/komari/internal/metricstore"
	v1 "github.com/komari-monitor/komari/protocol/v1"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

//go:embed static/* agent.py
var assets embed.FS

type Node struct {
	ID            string `gorm:"primaryKey" json:"id"`
	Name          string `json:"name"`
	TokenHash     string `json:"-"`
	EnrollHash    string `json:"-"`
	EnrollExpires int64  `json:"-"`
	LastSeen      int64  `json:"last_seen"`
	Quota         int64  `json:"quota"`
	Month         string `json:"month"`
	Up            int64  `json:"up"`
	Down          int64  `json:"down"`
	Metrics       string `json:"metrics"`
	Boot          string `json:"boot"`
	Seq           int64  `json:"-"`
}
type LoginSession struct {
	Hash    string `gorm:"primaryKey"`
	CSRF    string
	Expires int64
}
type Job struct {
	ID         string `gorm:"primaryKey" json:"id"`
	NodeID     string `gorm:"index" json:"node_id"`
	Title      string `json:"title"`
	Script     string `json:"-"`
	ScriptHash string `json:"script_hash"`
	State      string `json:"state"`
	Progress   int    `json:"progress"`
	Step       string `json:"step"`
	Logs       string `json:"logs"`
	Links      string `json:"links"`
	Timeout    int    `json:"timeout"`
	Created    int64  `json:"created"`
	Started    int64  `json:"started"`
	Updated    int64  `json:"updated"`
	Finished   int64  `json:"finished"`
	Seq        int64  `json:"-"`
	ExitCode   *int   `json:"exit_code"`
	Cancel     bool   `json:"cancel"`
}
type Audit struct {
	ID     uint   `gorm:"primaryKey" json:"id"`
	At     int64  `json:"at"`
	Action string `json:"action"`
	Target string `json:"target"`
}
type App struct {
	DB       *gorm.DB
	Origin   string
	Secure   bool
	mu       sync.Mutex
	loginMu  sync.Mutex
	Attempts map[string][]int64
}

func token() string {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return hex.EncodeToString(b)
}
func digest(v string) string                    { d := sha256.Sum256([]byte(v)); return hex.EncodeToString(d[:]) }
func fail(c *gin.Context, status int, s string) { c.AbortWithStatusJSON(status, gin.H{"error": s}) }
func bind(c *gin.Context, v any) bool {
	if e := c.ShouldBindJSON(v); e != nil {
		fail(c, 400, "输入格式有误")
		return false
	}
	return true
}
func (a *App) audit(action, target string) {
	a.DB.Create(&Audit{At: time.Now().Unix(), Action: action, Target: target})
}
func (a *App) sameOrigin(c *gin.Context) bool { return c.GetHeader("Origin") == a.Origin }
func (a *App) admin(c *gin.Context) {
	t, e := c.Cookie("lc_session")
	var s LoginSession
	if e != nil || a.DB.First(&s, "hash = ? AND expires > ?", digest(t), time.Now().Unix()).Error != nil {
		fail(c, 401, "请先登录")
		return
	}
	if c.Request.Method != "GET" && (!a.sameOrigin(c) || subtle.ConstantTimeCompare([]byte(c.GetHeader("X-CSRF-Token")), []byte(s.CSRF)) != 1) {
		fail(c, 403, "请求验证失败，请刷新页面")
		return
	}
	c.Set("session", s)
	c.Next()
}
func (a *App) agentAuth(c *gin.Context) {
	auth := c.GetHeader("Authorization")
	var n Node
	if !strings.HasPrefix(auth, "Bearer ") || a.DB.First(&n, "token_hash = ? AND token_hash <> ''", digest(strings.TrimPrefix(auth, "Bearer "))).Error != nil {
		fail(c, 401, "invalid agent credential")
		return
	}
	c.Set("node", n)
	c.Next()
}
func (a *App) login(c *gin.Context) {
	if !a.sameOrigin(c) {
		fail(c, 403, "请求来源不匹配")
		return
	}
	var p struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !bind(c, &p) {
		return
	}
	now := time.Now().Unix()
	host, _, _ := net.SplitHostPort(c.Request.RemoteAddr)
	a.loginMu.Lock()
	// Global budget prevents bypass through spoofed proxy headers or IP rotation.
	key := "all"
	_ = host
	recent := []int64{}
	for _, t := range a.Attempts[key] {
		if t > now-60 {
			recent = append(recent, t)
		}
	}
	if len(recent) >= 10 {
		a.loginMu.Unlock()
		fail(c, 429, "尝试过多，请一分钟后再试")
		return
	}
	a.Attempts[key] = append(recent, now)
	a.loginMu.Unlock()
	var u models.User
	e := a.DB.First(&u, "username = ?", p.Username).Error
	if e != nil || bcrypt.CompareHashAndPassword([]byte(u.Passwd), []byte(p.Password)) != nil {
		a.audit("login_failed", "")
		fail(c, 401, "账号或密码不正确")
		return
	}
	t := token()
	s := LoginSession{Hash: digest(t), CSRF: token(), Expires: now + 8*3600}
	if e = a.DB.Create(&s).Error; e != nil {
		fail(c, 500, "无法创建会话")
		return
	}
	http.SetCookie(c.Writer, &http.Cookie{Name: "lc_session", Value: t, Path: "/", Secure: a.Secure, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: 8 * 3600})
	a.audit("login", u.UUID)
	c.JSON(200, gin.H{"csrf": s.CSRF})
}
func (a *App) router() *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())
	_ = r.SetTrustedProxies(nil)
	r.Use(func(c *gin.Context) {
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 256*1024)
		c.Header("Cache-Control", "no-store")
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("Referrer-Policy", "no-referrer")
		c.Header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
		if a.Secure {
			c.Header("Strict-Transport-Security", "max-age=31536000")
		}
		c.Next()
	})
	for path, file := range map[string]string{"/": "static/index.html", "/app.js": "static/app.js", "/style.css": "static/style.css"} {
		f := file
		r.GET(path, func(c *gin.Context) {
			b, e := assets.ReadFile(f)
			if e != nil {
				fail(c, 500, "资源缺失")
				return
			}
			ct := "text/html; charset=utf-8"
			if strings.HasSuffix(f, ".js") {
				ct = "text/javascript; charset=utf-8"
			}
			if strings.HasSuffix(f, ".css") {
				ct = "text/css; charset=utf-8"
			}
			c.Data(200, ct, b)
		})
	}
	r.GET("/healthz", func(c *gin.Context) { c.JSON(200, gin.H{"status": "ok", "base": "Komari 1.4.3"}) })
	r.POST("/api/login", a.login)
	r.POST("/enroll", a.enroll)
	g := r.Group("/api", a.admin)
	g.GET("/session", func(c *gin.Context) { c.JSON(200, gin.H{"csrf": c.MustGet("session").(LoginSession).CSRF}) })
	g.POST("/logout", func(c *gin.Context) {
		s := c.MustGet("session").(LoginSession)
		a.DB.Delete(&s)
		http.SetCookie(c.Writer, &http.Cookie{Name: "lc_session", Value: "", Path: "/", MaxAge: -1, Secure: a.Secure, HttpOnly: true, SameSite: http.SameSiteStrictMode})
		c.JSON(200, gin.H{"ok": true})
	})
	g.GET("/nodes", func(c *gin.Context) {
		var n []Node
		if a.DB.Order("name").Find(&n).Error != nil {
			fail(c, 500, "读取失败")
			return
		}
		c.JSON(200, n)
	})
	g.POST("/nodes", a.addNode)
	g.POST("/nodes/:id/enrollment", a.enrollment)
	g.POST("/nodes/:id/revoke", a.revoke)
	g.POST("/nodes/:id/delete", a.deleteNode)
	g.POST("/nodes/:id/quota", a.quota)
	g.GET("/jobs", func(c *gin.Context) {
		a.expireJobs()
		var j []Job
		a.DB.Order("created desc").Limit(100).Find(&j)
		for i := range j {
			j[i].Logs = ""
		}
		c.JSON(200, j)
	})
	g.GET("/jobs/:id", func(c *gin.Context) {
		a.expireJobs()
		var j Job
		if a.DB.First(&j, "id = ?", c.Param("id")).Error != nil {
			fail(c, 404, "任务不存在")
			return
		}
		c.JSON(200, j)
	})
	g.POST("/jobs", a.createJob)
	g.POST("/jobs/:id/cancel", a.cancelJob)
	g.GET("/audit", func(c *gin.Context) { var v []Audit; a.DB.Order("id desc").Limit(100).Find(&v); c.JSON(200, v) })
	ag := r.Group("/agent", a.agentAuth)
	ag.GET("/code", func(c *gin.Context) { b, _ := assets.ReadFile("agent.py"); c.Data(200, "text/x-python", b) })
	ag.POST("/heartbeat", a.heartbeat)
	ag.POST("/poll", a.poll)
	ag.POST("/jobs/:id/events", a.events)
	return r
}
func (a *App) addNode(c *gin.Context) {
	var p struct {
		Name  string `json:"name"`
		Quota int64  `json:"quota"`
	}
	if !bind(c, &p) {
		return
	}
	p.Name = strings.TrimSpace(p.Name)
	if len(p.Name) < 1 || len(p.Name) > 100 || p.Quota < 0 || p.Quota > 1000000000000000 {
		fail(c, 400, "名称或流量额度无效")
		return
	}
	if p.Quota == 0 {
		p.Quota = 1000000000000
	}
	id := uuid.NewString()
	e := a.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&models.Client{UUID: id, Name: p.Name, Token: digest(token()), Hidden: true, TrafficLimit: p.Quota, TrafficLimitType: "sum"}).Error; err != nil {
			return err
		}
		return tx.Create(&Node{ID: id, Name: p.Name, Quota: p.Quota, Metrics: "{}"}).Error
	})
	if e != nil {
		fail(c, 500, "创建失败")
		return
	}
	a.audit("node_created", id)
	c.JSON(201, gin.H{"id": id})
}
func (a *App) enrollment(c *gin.Context) {
	t := token()
	res := a.DB.Model(&Node{}).Where("id = ?", c.Param("id")).Updates(map[string]any{"enroll_hash": digest(t), "enroll_expires": time.Now().Unix() + 900})
	if res.Error != nil || res.RowsAffected != 1 {
		fail(c, 404, "服务器不存在")
		return
	}
	// The bootstrap secret is short-lived and one-use. No permanent token in user-data.
	script := "#!/bin/bash\nset -euo pipefail\numask 077\nexport DEBIAN_FRONTEND=noninteractive\napt-get -o DPkg::Lock::Timeout=180 update\napt-get -o DPkg::Lock::Timeout=180 install -y curl ca-certificates python3\nf=$(mktemp)\ntrap 'rm -f \"$f\"' EXIT\ncurl --proto '=https' --tlsv1.2 --fail --silent --show-error --max-time 30 -X POST -H 'Authorization: Bearer " + t + "' '" + a.Origin + "/enroll' -o \"$f\"\nbash \"$f\"\n"
	a.audit("enrollment_issued", c.Param("id"))
	c.JSON(200, gin.H{"script": script, "expires_in": 900})
}
func (a *App) enroll(c *gin.Context) {
	h := c.GetHeader("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		fail(c, 401, "invalid enrollment")
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	var n Node
	if a.DB.First(&n, "enroll_hash = ? AND enroll_expires > ?", digest(strings.TrimPrefix(h, "Bearer ")), time.Now().Unix()).Error != nil {
		fail(c, 401, "enrollment expired or already used")
		return
	}
	t := token()
	if e := a.DB.Model(&n).Updates(map[string]any{"token_hash": digest(t), "enroll_hash": "", "enroll_expires": 0}).Error; e != nil {
		fail(c, 500, "enrollment failed")
		return
	}
	code, _ := assets.ReadFile("agent.py")
	sum := digest(string(code))
	cfg, _ := json.Marshal(map[string]any{"endpoint": a.Origin, "token": t, "node_id": n.ID})
	script := fmt.Sprintf(`#!/bin/bash
set -euo pipefail
umask 077
install -d -m 700 /etc/lightsail-control /var/lib/lightsail-control /opt/lightsail-control
cat > /etc/lightsail-control/agent.json <<'LC_CONFIG'
%s
LC_CONFIG
curl --proto '=https' --tlsv1.2 --fail --silent --show-error --max-time 60 -H 'Authorization: Bearer %s' '%s/agent/code' -o /opt/lightsail-control/agent.py
printf '%%s  %%s\n' '%s' '/opt/lightsail-control/agent.py' | sha256sum -c -
chmod 600 /etc/lightsail-control/agent.json /opt/lightsail-control/agent.py
cat > /etc/systemd/system/lightsail-control.service <<'LC_UNIT'
[Unit]
Description=Lightsail Control agent (Komari)
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 /opt/lightsail-control/agent.py
Restart=on-failure
RestartSec=5
UMask=0077
KillMode=control-group
TimeoutStopSec=15
[Install]
WantedBy=multi-user.target
LC_UNIT
systemctl daemon-reload
systemctl enable lightsail-control.service
systemctl restart lightsail-control.service
printf 'Lightsail Control agent installed.\n'
`, cfg, t, a.Origin, sum)
	a.audit("node_enrolled", n.ID)
	c.Data(200, "text/x-shellscript", []byte(script))
}
func (a *App) revoke(c *gin.Context) {
	a.mu.Lock()
	defer a.mu.Unlock()
	res := a.DB.Model(&Node{}).Where("id = ?", c.Param("id")).Updates(map[string]any{"token_hash": "", "enroll_hash": "", "last_seen": 0})
	if res.Error != nil || res.RowsAffected != 1 {
		fail(c, 404, "服务器不存在")
		return
	}
	a.DB.Model(&Job{}).Where("node_id = ? AND state IN ?", c.Param("id"), []string{"queued", "claimed", "running"}).Updates(map[string]any{"state": "revoked", "cancel": true, "finished": time.Now().Unix()})
	a.audit("node_revoked", c.Param("id"))
	c.JSON(200, gin.H{"ok": true})
}
func (a *App) deleteNode(c *gin.Context) {
	a.mu.Lock()
	defer a.mu.Unlock()
	id := c.Param("id")
	err := a.DB.Transaction(func(tx *gorm.DB) error {
		var n Node
		if err := tx.First(&n, "id = ?", id).Error; err != nil {
			return err
		}
		if err := tx.Model(&Job{}).Where("node_id = ? AND state IN ?", id, []string{"queued", "claimed", "running"}).Updates(map[string]any{"state": "revoked", "cancel": true, "finished": time.Now().Unix(), "step": "服务器已从控制中心删除"}).Error; err != nil {
			return err
		}
		if err := tx.Where("uuid = ?", id).Delete(&models.Client{}).Error; err != nil {
			return err
		}
		if err := tx.Delete(&n).Error; err != nil {
			return err
		}
		return tx.Create(&Audit{At: time.Now().Unix(), Action: "node_deleted", Target: id + ":" + n.Name}).Error
	})
	if err == gorm.ErrRecordNotFound {
		fail(c, 404, "服务器不存在")
		return
	}
	if err != nil {
		fail(c, 500, "删除失败，请重试")
		return
	}
	c.JSON(200, gin.H{"ok": true})
}
func (a *App) quota(c *gin.Context) {
	var p struct {
		Quota int64 `json:"quota"`
	}
	if !bind(c, &p) {
		return
	}
	if p.Quota < 1 || p.Quota > 1000000000000000 {
		fail(c, 400, "额度超出范围")
		return
	}
	res := a.DB.Model(&Node{}).Where("id = ?", c.Param("id")).Update("quota", p.Quota)
	if res.Error != nil || res.RowsAffected != 1 {
		fail(c, 404, "服务器不存在")
		return
	}
	a.audit("quota_changed", c.Param("id"))
	c.JSON(200, gin.H{"ok": true})
}

func (a *App) createJob(c *gin.Context) {
	var p struct {
		NodeID  string `json:"node_id"`
		Title   string `json:"title"`
		Script  string `json:"script"`
		Timeout int    `json:"timeout"`
	}
	if !bind(c, &p) {
		return
	}
	if len(p.Script) == 0 || len(p.Script) > 65536 || len(p.Title) > 100 || p.Timeout < 60 || p.Timeout > 7200 {
		fail(c, 400, "脚本最多 64 KB，超时范围 60–7200 秒")
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	var n Node
	if a.DB.First(&n, "id = ?", p.NodeID).Error != nil || n.TokenHash == "" || n.LastSeen < time.Now().Unix()-30 {
		fail(c, 409, "服务器离线，暂不能下发")
		return
	}
	var count int64
	a.DB.Model(&Job{}).Where("node_id = ? AND state IN ?", p.NodeID, []string{"queued", "claimed", "running"}).Count(&count)
	if count > 0 {
		fail(c, 409, "该服务器已有未结束任务")
		return
	}
	now := time.Now().Unix()
	j := Job{ID: uuid.NewString(), NodeID: p.NodeID, Title: p.Title, Script: p.Script, ScriptHash: digest(p.Script), State: "queued", Links: "[]", Timeout: p.Timeout, Created: now, Updated: now}
	if e := a.DB.Create(&j).Error; e != nil {
		fail(c, 500, "保存任务失败")
		return
	}
	a.audit("job_created", j.ID+":"+j.ScriptHash)
	c.JSON(201, j)
}
func (a *App) expireJobs() {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now().Unix()
	a.DB.Model(&Job{}).Where("state = 'queued' AND created < ?", now-600).Updates(map[string]any{"state": "expired", "finished": now, "step": "排队超时，未执行"})
	a.DB.Model(&Job{}).Where("state IN ? AND updated < ?", []string{"claimed", "running"}, now-120).Updates(map[string]any{"state": "interrupted", "cancel": true, "finished": now, "step": "回传中断，结果未知；未自动重试"})
}
func (a *App) cancelJob(c *gin.Context) {
	a.mu.Lock()
	defer a.mu.Unlock()
	var j Job
	if a.DB.First(&j, "id = ?", c.Param("id")).Error != nil {
		fail(c, 404, "任务不存在")
		return
	}
	if j.State == "queued" {
		j.State = "cancelled"
		j.Finished = time.Now().Unix()
	}
	j.Cancel = true
	if a.DB.Save(&j).Error != nil {
		fail(c, 500, "取消失败")
		return
	}
	a.audit("job_cancel_requested", j.ID)
	c.JSON(200, j)
}
func (a *App) poll(c *gin.Context) {
	a.expireJobs()
	a.mu.Lock()
	defer a.mu.Unlock()
	n := c.MustGet("node").(Node)
	var j Job
	if a.DB.Where("node_id = ? AND state = 'queued'", n.ID).Order("created").First(&j).Error != nil {
		c.JSON(200, gin.H{"job": nil})
		return
	}
	j.State = "claimed"
	j.Updated = time.Now().Unix()
	if a.DB.Save(&j).Error != nil {
		fail(c, 500, "领取失败")
		return
	}
	c.JSON(200, gin.H{"job": gin.H{"id": j.ID, "script": j.Script, "sha256": j.ScriptHash, "timeout": j.Timeout}})
}

type Event struct {
	Seq      int64    `json:"seq"`
	State    string   `json:"state"`
	Progress *int     `json:"progress"`
	Step     string   `json:"step"`
	Log      string   `json:"log"`
	Links    []string `json:"links"`
	ExitCode *int     `json:"exit_code"`
}

func validLink(s string) bool {
	if len(s) > 8192 || strings.ContainsAny(s, "\r\n\x00") {
		return false
	}
	u, e := url.Parse(s)
	if e != nil {
		return false
	}
	switch u.Scheme {
	case "https", "http", "vless", "vmess", "trojan", "ss":
		return u.Host != ""
	}
	return false
}
func (a *App) events(c *gin.Context) {
	var p Event
	if !bind(c, &p) {
		return
	}
	if p.Seq < 1 || len(p.Log) > 32768 || len(p.Step) > 300 || len(p.Links) > 20 {
		fail(c, 400, "event too large")
		return
	}
	for _, l := range p.Links {
		if !validLink(l) {
			fail(c, 400, "invalid result link")
			return
		}
	}
	if p.Progress != nil && (*p.Progress < 0 || *p.Progress > 100) {
		fail(c, 400, "invalid progress")
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	n := c.MustGet("node").(Node)
	var j Job
	if a.DB.First(&j, "id = ? AND node_id = ?", c.Param("id"), n.ID).Error != nil {
		fail(c, 404, "job not found")
		return
	}
	if j.State != "claimed" && j.State != "running" {
		c.JSON(200, gin.H{"stop": true, "ack": j.Seq})
		return
	}
	if p.Seq <= j.Seq {
		c.JSON(200, gin.H{"stop": j.Cancel, "ack": j.Seq})
		return
	}
	if p.Seq != j.Seq+1 {
		fail(c, 409, "event sequence gap")
		return
	}
	now := time.Now().Unix()
	switch p.State {
	case "running":
		if j.Started == 0 {
			j.Started = now
		}
		j.State = "running"
	case "succeeded":
		if p.ExitCode == nil || *p.ExitCode != 0 || j.Started == 0 {
			fail(c, 400, "success requires a started job and zero exit code")
			return
		}
		j.State = "succeeded"
		j.Progress = 100
		j.Finished = now
	case "failed", "cancelled", "timed_out", "interrupted":
		j.State = p.State
		j.Finished = now
	default:
		fail(c, 400, "invalid state")
		return
	}
	if j.Cancel && j.State == "succeeded" {
		j.State = "cancelled"
		j.Progress = 0
	}
	if p.Progress != nil && j.State == "running" && *p.Progress > j.Progress {
		j.Progress = *p.Progress
		if j.Progress > 99 {
			j.Progress = 99
		}
	}
	if p.Step != "" {
		j.Step = p.Step
	}
	j.Seq = p.Seq
	j.Updated = now
	j.ExitCode = p.ExitCode
	j.Logs += p.Log
	if len(j.Logs) > 1024*1024 {
		j.Logs = j.Logs[len(j.Logs)-1024*1024:]
	}
	if p.Links != nil {
		b, _ := json.Marshal(p.Links)
		j.Links = string(b)
	}
	if e := a.DB.Save(&j).Error; e != nil {
		fail(c, 500, "save failed")
		return
	}
	if j.Finished > 0 {
		a.audit("job_"+j.State, j.ID)
	}
	c.JSON(200, gin.H{"stop": j.Cancel, "ack": j.Seq})
}
func (a *App) heartbeat(c *gin.Context) {
	var p struct {
		Report v1.Report `json:"report"`
		OS     string    `json:"os"`
		Arch   string    `json:"arch"`
		IP     string    `json:"ip"`
		Boot   string    `json:"boot"`
		Seq    int64     `json:"seq"`
		Month  string    `json:"month"`
		Up     int64     `json:"up"`
		Down   int64     `json:"down"`
	}
	if !bind(c, &p) {
		return
	}
	n := c.MustGet("node").(Node)
	now := time.Now().UTC()
	if p.Month != now.Format("2006-01") || p.Up < 0 || p.Down < 0 || p.Up > 1e16 || p.Down > 1e16 || p.Seq < 1 || len(p.Boot) > 80 || len(p.OS) > 100 || len(p.Arch) > 50 {
		fail(c, 400, "invalid counters or clock")
		return
	}
	p.Report.UUID = n.ID
	p.Report.UpdatedAt = now
	if e := clients.ReportVerify(p.Report); e != nil {
		fail(c, 400, "invalid metrics")
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	// Refresh under lock so parallel reports cannot overwrite newer samples.
	if a.DB.First(&n, "id = ?", n.ID).Error != nil {
		fail(c, 404, "node not found")
		return
	}
	if n.Boot == p.Boot && p.Seq <= n.Seq {
		c.JSON(200, gin.H{"ok": true})
		return
	}
	if n.Month == p.Month && (p.Up < n.Up || p.Down < n.Down) {
		fail(c, 409, "monthly counters decreased; preserve agent state")
		return
	}
	if _, e := metricstore.WriteReport(c.Request.Context(), p.Report); e != nil {
		fail(c, 500, "metric store failed")
		return
	}
	b, _ := json.Marshal(p.Report)
	n.Metrics = string(b)
	n.LastSeen = now.Unix()
	n.Month = p.Month
	n.Up = p.Up
	n.Down = p.Down
	n.Seq = p.Seq
	n.Boot = p.Boot
	if e := a.DB.Save(&n).Error; e != nil {
		fail(c, 500, "save failed")
		return
	}
	info := map[string]any{"os": p.OS, "arch": p.Arch, "mem_total": p.Report.Ram.Total, "disk_total": p.Report.Disk.Total, "cpu_cores": p.Report.CPU.Cores}
	if ip := net.ParseIP(p.IP); ip != nil {
		if ip.To4() != nil {
			info["ipv4"] = p.IP
		} else {
			info["ipv6"] = p.IP
		}
	}
	a.DB.Model(&models.Client{}).Where("uuid = ?", n.ID).Updates(info)
	c.JSON(200, gin.H{"ok": true})
}
func initDB() (*gorm.DB, error) {
	if e := os.MkdirAll("data", 0700); e != nil {
		return nil, e
	}
	flags.DatabaseType = "sqlite"
	flags.DatabaseFile = "./data/komari.db"
	if e := dbcore.Initialize(); e != nil {
		return nil, e
	}
	db := dbcore.GetDBInstance()
	if e := db.AutoMigrate(&Node{}, &Job{}, &LoginSession{}, &Audit{}); e != nil {
		return nil, e
	}
	if e := metricstore.InitializeStore(); e != nil {
		return nil, e
	}
	return db, nil
}
func initializeAdmin(db *gorm.DB) error {
	var count int64
	if e := db.Model(&models.User{}).Count(&count).Error; e != nil {
		return e
	}
	if count > 0 {
		return nil
	}
	path := os.Getenv("LC_ADMIN_PASSWORD_FILE")
	if path == "" {
		return errors.New("LC_ADMIN_PASSWORD_FILE required for first startup")
	}
	b, e := os.ReadFile(path)
	if e != nil {
		return e
	}
	p := strings.TrimSpace(string(b))
	if len(p) < 16 || len(p) > 72 {
		return errors.New("initial password must be 16–72 bytes")
	}
	h, e := bcrypt.GenerateFromPassword([]byte(p), 12)
	if e != nil {
		return e
	}
	name := os.Getenv("LC_ADMIN_USER")
	if name == "" {
		name = "admin"
	}
	return db.Create(&models.User{UUID: uuid.NewString(), Username: name, Passwd: string(h)}).Error
}
func main() {
	origin := strings.TrimRight(os.Getenv("LC_PUBLIC_URL"), "/")
	u, e := url.Parse(origin)
	secure := e == nil && u.Scheme == "https" && u.Host != "" && u.Path == "" && u.RawQuery == "" && u.Fragment == "" && u.User == nil
	testHTTP := os.Getenv("LC_LOCAL_TEST") == "1" && e == nil && u.Scheme == "http" && (u.Hostname() == "127.0.0.1" || u.Hostname() == "localhost")
	if !secure && !testHTTP {
		log.Fatal("LC_PUBLIC_URL must be a clean https origin")
	}
	db, e := initDB()
	if e != nil {
		log.Fatal(e)
	}
	defer dbcore.Close()
	defer metricstore.CloseStoreContext(context.Background())
	if e = initializeAdmin(db); e != nil {
		log.Fatal(e)
	}
	a := &App{DB: db, Origin: origin, Secure: secure, Attempts: map[string][]int64{}}
	addr := os.Getenv("LC_LISTEN")
	if addr == "" {
		addr = "127.0.0.1:8080"
	}
	srv := &http.Server{Addr: addr, Handler: a.router(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 20 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16384}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				a.expireJobs()
				db.Where("expires < ?", time.Now().Unix()).Delete(&LoginSession{})
				_, _ = metricstore.Compact(ctx, time.Now().UTC())
				_, _ = metricstore.CleanupExpired(ctx, time.Now().UTC())
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		<-ctx.Done()
		c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(c)
	}()
	log.Printf("Lightsail Control (Komari 1.4.3) listening on %s", addr)
	if e = srv.ListenAndServe(); e != nil && e != http.ErrServerClosed {
		log.Fatal(e)
	}
}
