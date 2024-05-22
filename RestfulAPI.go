package main

import (
    "database/sql" // Lots of bloat here from old versions which used previously needed packages
    "github.com/gin-gonic/gin"
    _"github.com/mattn/go-sqlite3"
    "golang.org/x/crypto/bcrypt"
    "log"
    "net"
    "fmt"
    _"strconv"
    "time"
    "flag"
    _"net/http"
    "encoding/json"
    "os"
    _"github.com/nickname32/discordhook"
    _"strings"
    "github.com/fatih/color"
    _"github.com/andersfylling/snowflake"
    _"io/ioutil"
)

type DiscordMessage struct { // Structure for the discord webhook embed (Depreciated)
    content string
    embeds string
    username string
    avatar_url string
}

type Configuration struct { // Structure for the config JSON file
    TeleLogging struct {
        TelegramLoggin bool
        TelegramBotAuth string
        TelegramChannelID string
    }
    DiscordLogging struct {
        DiscordLoggin bool
        DiscordWebhookID uint64
        WebhookName string
        AvatarURL string
        DiscordWebhookToken string
        DiscordWebhookMessage string
    }
    Info struct{
        BindPort string
        Cloudflare bool
        Timeout time.Duration
    }
}

var Config = flag.String("h", "./config.json", "Please specify the config file.")

func GetOutboundIP() net.IP {
    conn, err := net.Dial("udp", "8.8.8.8:80")
    if err != nil {
        log.Fatal(err)
    }
    defer conn.Close()

    localAddr := conn.LocalAddr().(*net.UDPAddr)

    return localAddr.IP
}

func main() { // Start the webserver
    flag.Parse()
    file, err := os.Open(*Config)
    if err != nil {
        log.Fatal("[ ERROR ] Can't open config file: ", err)
    }
    defer file.Close()
    decoder := json.NewDecoder(file)
    Config := Configuration{}
    err = decoder.Decode(&Config)
    if err != nil {
        log.Fatal("[ ERROR ] Can't decode config JSON: ", err)
    }
   
    
    gin.SetMode(gin.ReleaseMode)
    router := gin.Default()
    router.POST("/hidden/user/register", userCreate)
    color.White("API Check")
    
    fmt.Println(color.WhiteString(" [ CONFIG ] Webserver Started On:"), GetOutboundIP(), ":", Config.Info.BindPort)

    if ! Config.TeleLogging.TelegramLoggin { 
        fmt.Println(color.WhiteString(" [ CONFIG ] Telegram Logging:"), color.RedString("false"))
    } else {
        fmt.Println(color.WhiteString(" [ CONFIG ] Telegram Logging:"), color.GreenString("true"))
    }
    if ! Config.DiscordLogging.DiscordLoggin {
        fmt.Println(color.WhiteString(" [ CONFIG ] Discord Logging:"), color.RedString("false"))
    } else {
        fmt.Println(color.WhiteString(" [ CONFIG ] Discord Logging:"), color.GreenString("true"))
    }
    if ! Config.Info.Cloudflare {
        fmt.Println(color.WhiteString(" [ CONFIG ] Linked To Cloudflare:"), color.RedString("false"))
    } else {
        fmt.Println(color.WhiteString(" [ CONFIG ] Linked To Cloudflare:"), color.GreenString("true"))
    }
    
    router.Run(":"+Config.Info.BindPort)
}

func userCreate(c *gin.Context) { // Main controller

    Config := Configuration{} // Class the config file

    var clientIP string
    if ! Config.Info.Cloudflare {
        clientIP = c.ClientIP()
    } else {
        clientIP = c.Request.Header.Get("CF-Connecting-IP")
    }

    current_time := time.Now().UTC()
    current_time_format := current_time.Format("2006-01-02 15:04:05") // Grabbing the time for logging purposes

    username := c.DefaultQuery("user", "None") // Defaulting the parameters to None for easier error checking
    email := c.DefaultQuery("email", "None")
    password := c.DefaultQuery("password", "None")

    sqliteDatabase, err := sql.Open("sqlite3", "./main.sqlite") // Ensuring the database can be opened
    if err != nil{
        log.Fatal("[ DATABASE ERROR ]", err.Error())
    }

    if ! checkParams(username, email, password) { 
        failed := gin.H{"Status": "Failed", "Reason": "Invalid parameters"}
        c.JSON(400, failed)
        return 
    }

    if emailDuplicationCheck(sqliteDatabase, email) {
        failed := gin.H{"Status": "Failed", "Reason": "Email is already in use"}
        c.JSON(400, failed)
        return 
    }

    if userDuplicationCheck(sqliteDatabase, username) {
        failed := gin.H{"Status": "Failed", "Reason": "Username is already in use"}
        c.JSON(400, failed)
        return 
    }

    passwordhashed := hashPassword(password)

    go addUser(sqliteDatabase, username, email, passwordhashed)
    go addLog(sqliteDatabase, clientIP, username+" "+email, "Success", current_time_format)
    Success := gin.H{"Status": "Success", "Reason": "User created successfully"}
    c.JSON(200,Success)
}

func checkParams(username string, email string, password string) bool { // This should be checked on the frontend however this must be added to prevent crashing incase of a direct request
    if username == "None" || email == "None" || password == "None"  {
        return false
    }else {
        return true
    }
}

func emailDuplicationCheck(db *sql.DB, email string) bool { // Checking if the email is already in use
    err := db.QueryRow("SELECT email FROM users WHERE email = ?", email).Scan(&email)
    if err != nil {
        if err != sql.ErrNoRows {
            log.Fatal("[ ERROR ] Cannot Access Table", err)
        }
        return false
    }
    return true
}

func userDuplicationCheck(db *sql.DB, username string) bool { // Checking if the username is already in use
    err := db.QueryRow("SELECT username FROM users WHERE username = ?", username).Scan(&username)
    if err != nil {
        if err != sql.ErrNoRows {
            log.Fatal("[ ERROR ] Cannot Access Table", err)
        }
        return false
    }
    return true
}

func hashPassword(password string) string { // This will be used to hash the users password to prevent databreaches causing important user data leakage
    bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
    if err != nil {
        log.Fatal("[ ERROR ] Cannot create a hash password", err)
    }
    return string(bytes)
}

func addUser(db *sql.DB, username string, email string, password string) { // Finally add the user to the database
    create, err := db.Prepare("INSERT INTO users(username, email, password) VALUES (?, ?, ?)")
    if err != nil {
        log.Fatal("[ ERROR] Cannot prepare the statement")
    }
    _, errr := create.Exec(username, email, password)
    if errr != nil {
        log.Fatal(err)
    }
}

func addLog(db *sql.DB, clientIP string, params string, result string, time string) { // Logging interations
    logging, err := db.Prepare("INSERT INTO logs(IPv4, params, result, time) VALUES (?, ?, ?, ?)")
    if err != nil {
        log.Fatal("[ ERROR] Cannot prepare the statement", err)
    }
    _, errr := logging.Exec(clientIP, params, result, time)
    if errr != nil {
        log.Fatal(err)
    }
}