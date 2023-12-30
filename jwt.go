package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/gin-gonic/gin"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"log"
	"strings"
	"time"
)

type UserInfo struct {
	ID       uint   `json:"id"`
	UserName string `json:"user_name"`
	Password string `json:"password"`
}

type JWT struct {
	Jwt string `json:"jwt"`
}

type Header struct {
	Alg string
	Typ string
}

type Data struct {
	Name string
	Iat  string
}

type Signature struct {
	Src string
	Key string
}

// 打开数据库
func OpenDB() (*gorm.DB, error) {
	dsn := "root:050109@tcp(127.0.0.1:3306)/example?charset=utf8mb4&parseTime=True&loc=Local"
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
		return nil, err
	}
	return db, nil
}

// HS256加密
func HmacSHA256(src, key string) string {
	m := hmac.New(sha256.New, []byte(key))
	m.Write([]byte(src))
	fmt.Println(hex.EncodeToString(m.Sum(nil)))
	return hex.EncodeToString(m.Sum(nil))
}

// base64编码
func b64(src string) string {
	src = base64.StdEncoding.EncodeToString([]byte(src))
	return src
}

func JwtGen(name string) string {
	header := Header{"HS256", "JWT"}
	var data Data
	var sgt Signature

	data.Name = name
	timeFormat := "2006-01-02 15:04:05"
	data.Iat = time.Now().Format(timeFormat)

	sgt.Src = b64(header.Alg+header.Alg) + "." + b64(data.Name+data.Iat)
	sgt.Key = "bainianzzz"
	J := sgt.Src + "." + HmacSHA256(sgt.Src, sgt.Key)
	return J
}

// 登陆界面
func login(c *gin.Context) {
	db, _ := OpenDB()

	var userSend, userDB UserInfo
	if err := c.BindJSON(&userSend); err != nil {
		log.Println("信息写入结构体未成功", err)
	}

	if err := db.Where("user_name=?", userSend.UserName).Find(&userDB).Error; err != nil {
		log.Println(err)
	}
	if userSend.Password == userDB.Password {
		jwt := JwtGen(userDB.UserName)
		c.String(200, jwt)
	} else {
		c.String(404, "用户不存在")
	}
}

// 验证jwt
func vip(c *gin.Context) {
	var J JWT
	if err := c.BindJSON(&J); err != nil {
		log.Println(err)
	}

	parts := strings.Split(J.Jwt, ".")
	Src := parts[0] + "." + parts[1]
	sign := HmacSHA256(Src, "bainianzzz")
	if sign == parts[2] {
		c.String(200, "欢迎回来")
	} else {
		c.Redirect(301, "/")
	}
}

func main() {
	r := gin.Default()

	r.GET("/", func(c *gin.Context) {
		c.String(200, "hello")
	})
	r.POST("/login", login)
	r.POST("/vip", vip)

	if err := r.Run(":8080"); err != nil {
		log.Fatal(err)
	}
}
