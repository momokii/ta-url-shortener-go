package controllers

import (
	"database/sql"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"ta-url-shortener-go/db"
	"ta-url-shortener-go/models"
	"ta-url-shortener-go/utils"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

// * ------------------ FUNCTION
// Custom password validation
func validatePassword(fl validator.FieldLevel) bool {
	password := fl.Field().String()
	re := regexp.MustCompile(`^(?=.*[0-9])(?=.*[A-Z]).{6,}$`)
	return re.MatchString(password)
}

// * ------------------ CONTROLLER
func CheckSelf(c *gin.Context) {
	var user models.UserModelRes

	userData, exist := c.Get("user")
	if !exist {
		utils.ThrowErr(c, http.StatusUnauthorized, "Need Header Auth")
		return
	}

	user.Id = userData.(models.UserModel).Id
	user.Username = userData.(models.UserModel).Username
	user.Name = userData.(models.UserModel).Name
	user.Role = userData.(models.UserModel).Role
	user.IsActive = userData.(models.UserModel).IsActive

	c.JSON(http.StatusOK, gin.H{
		"errors":  false,
		"message": "get self data",
		"data":    user,
	})
}

func GetAllUser(c *gin.Context) {
	db_select := utils.DBSelect(c)

	var users []models.UserModelRes
	var total_user int

	// * pagination
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	size, _ := strconv.Atoi(c.DefaultQuery("per_page", "10"))
	offset := (page - 1) * size
	search := c.DefaultQuery("search", "")
	user_type := c.DefaultQuery("user_type", "")
	is_active_q := c.DefaultQuery("is_active", "")
	var is_active bool
	if (is_active_q == "1") || (is_active_q == "") {
		is_active = true
	} else {
		is_active = false
	}

	if db_select == "sql" {
		query := "SELECT id, username, name, role, is_active FROM users WHERE 1=1"

		if search != "" {
			query += " AND (username ILIKE '%" + search + "%' OR name ILIKE '%" + search + "%')"
		}
		if user_type != "" {
			query += " AND role = " + user_type
		}

		query += " AND is_active = " + strconv.FormatBool(is_active)
		baseQuery := query

		err := db.DB.QueryRow("SELECT COUNT(*) FROM (" + baseQuery + ") AS total").Scan(&total_user)
		if err != nil {
			utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
			return
		}

		userRows, err := db.DB.Query(baseQuery+" ORDER BY id LIMIT $1 OFFSET $2", size, offset)
		if err != nil {
			utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
			return
		}
		defer userRows.Close()

		for userRows.Next() {
			var user models.UserModelRes
			err := userRows.Scan(&user.Id, &user.Username, &user.Name, &user.Role, &user.IsActive)
			if err != nil {
				utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
				return
			}
			users = append(users, user)
		}

	} else {
		query := bson.M{
			"is_active": is_active,
		}
		if search != "" {
			query["$or"] = []bson.M{
				bson.M{"username": bson.M{"$regex": search, "$options": "i"}},
				bson.M{"name": bson.M{"$regex": search, "$options": "i"}},
			}
		}
		if user_type != "" {
			roleInt, err := strconv.Atoi(user_type)
			if err != nil {
				utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
				return
			}
			query["role"] = roleInt
		}

		total, err := db.Collections.UserCollection.CountDocuments(c, query)
		if err != nil {
			utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
			return
		}
		total_user = int(total)

		size64 := int64(size)
		offset64 := int64(offset)
		userRows, err := db.Collections.UserCollection.Find(c, query, &options.FindOptions{
			Limit: &size64,
			Skip:  &offset64,
		})
		if err != nil {
			utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
			return
		}

		if err = userRows.All(c, &users); err != nil {
			utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
			return
		}

	}

	// make sure if users is nil to return empty array
	if users == nil {
		users = []models.UserModelRes{}
	}

	c.JSON(http.StatusOK, gin.H{
		"errors":  false,
		"message": "info user detail",
		"data": gin.H{
			"page":       page,
			"per_page":   size,
			"total_data": total_user,
			"users":      users,
		},
	})
}

func GetUserByUsername(c *gin.Context) {
	db_select := utils.DBSelect(c)

	username := c.Params.ByName("username")
	var user models.UserModelRes
	var links []models.LinkModelRes

	if db_select == "sql" {

		err := db.DB.QueryRow("SELECT id, username, name, role, is_active FROM users WHERE username = $1", username).Scan(&user.Id, &user.Username, &user.Name, &user.Role, &user.IsActive)
		if err != nil {
			utils.ThrowErr(c, http.StatusNotFound, "user not found")
			return
		}

		linkRows, err := db.DB.Query("SELECT id, long_link, short_link, user_id, last_visited, total_visited, created_at, updated_at FROM urls WHERE user_id = $1", user.Id)
		if err != nil {
			utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
			return
		}
		defer linkRows.Close()

		for linkRows.Next() {
			var timeSql sql.NullTime
			var link models.LinkModelRes
			err := linkRows.Scan(&link.Id, &link.LongLink, &link.ShortLink, &link.UserId, &timeSql, &link.TotalVisited, &link.CreatedAt, &link.UpdatedAt)
			if err != nil {
				utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
				return
			}

			if timeSql.Valid {
				link.LastVisited = timeSql.Time
			}

			links = append(links, link)
		}

	} else {

		err := db.Collections.UserCollection.FindOne(c, bson.M{"username": username}).Decode(&user)
		if err != nil {
			if err == mongo.ErrNoDocuments {
				utils.ThrowErr(c, http.StatusUnauthorized, "Username or Password is wrong")
			} else {
				utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
			}
			return
		}

		id, err := primitive.ObjectIDFromHex(user.Id)
		if err != nil {
			utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
			return
		}

		linkRows, err := db.Collections.LinkCollection.Find(c, bson.M{"user_id": id})
		if err != nil {
			utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
			return
		}

		if err = linkRows.All(c, &links); err != nil {
			utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
			return
		}
	}

	if links == nil {
		links = []models.LinkModelRes{}
	}

	c.JSON(http.StatusOK, gin.H{
		"errors":  false,
		"message": "Info User",
		"data": gin.H{
			"id":        user.Id,
			"username":  user.Username,
			"name":      user.Name,
			"role":      user.Role,
			"is_active": user.IsActive,
			"links":     links,
		},
	})
}

// TODO untested
func CreateUser(c *gin.Context) {
	db_select := utils.DBSelect(c)

	type DataUserCreate struct {
		Username string `json:"username" binding:"required,alphanum,min=5"`
		Password string `json:"password" binding:"required,passwd"`
		Name     string `json:"name" binding:"required"`
		Role     int    `json:"role" binding:"required"`
	}

	// Custom error messages
	var customErrorMessages = map[string]string{
		"Username": "Username must be alphanumeric and at least 5 characters long",
		"Password": "Password atleast using 1 number and 1 uppercase with minimum length 6 characterr",
	}

	var dataUser DataUserCreate
	var user models.UserModel
	// Password validation function
	validate := validator.New()
	validate.RegisterValidation("passwd", validatePassword)

	err := c.ShouldBindJSON(&dataUser)
	if err != nil {
		utils.ThrowErr(c, http.StatusBadRequest, err.Error())
		return
	}

	if err := validate.Struct(dataUser); err != nil {
		for _, err := range err.(validator.ValidationErrors) {
			fieldName := err.Field()
			errorMessage := customErrorMessages[fieldName]
			utils.ThrowErr(c, http.StatusBadRequest, errorMessage)
			return
		}
	}

	// hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(dataUser.Password), 16)
	if err != nil {
		utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
		return
	}

	if db_select == "sql" {

		err := db.DB.QueryRow("SELECT id FROM users WHERE username = $1", dataUser.Username).Scan(&user.Id)
		if err != nil && err != sql.ErrNoRows {
			utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
			return
		}

		if user.Id != "" {
			utils.ThrowErr(c, http.StatusUnauthorized, "Username is used, try using another username")
			return
		}

		_, err = db.DB.Exec("INSERT INTO users (username, password, name, role, is_active, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, NOW(), NOW()) RETURNING id", dataUser.Username, string(hashedPassword), dataUser.Name, dataUser.Role, true)
		if err != nil {
			utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
			return
		}

	} else {
		err := db.Collections.UserCollection.FindOne(c, bson.M{"username": dataUser.Username}).Decode(&user)
		if err != nil && err != mongo.ErrNoDocuments {
			utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
			return
		}

		if user.Id != "" {
			utils.ThrowErr(c, http.StatusUnauthorized, "Username is used, try using another username")
			return
		}

		timeNow := time.Now()

		db.Collections.UserCollection.InsertOne(c, bson.M{
			"username":   dataUser.Username,
			"password":   string(hashedPassword),
			"name":       dataUser.Name,
			"role":       dataUser.Role,
			"is_active":  true,
			"created_at": timeNow,
			"updated_at": timeNow,
		})

	}

	c.JSON(http.StatusOK, gin.H{
		"errors":  false,
		"message": "Success create new account",
	})
}

// TODO untested
func ChangePassword(c *gin.Context) {
	db_select := utils.DBSelect(c)

	type ChangePasswordInput struct {
		PasswordNow string `json:"password_now" binding:"required"`
		PasswordNew string `json:"new_password" binding:"required,passwd"`
	}
	var userInput ChangePasswordInput
	var tx *sql.Tx
	var session mongo.Session

	reqUser, exist := c.Get("user")
	if !exist {
		utils.ThrowErr(c, http.StatusUnauthorized, "Need Header Auth")
		return
	}

	err := c.ShouldBindJSON(&userInput)
	if err != nil {
		utils.ThrowErr(c, http.StatusBadRequest, err.Error())
		return
	}

	validate := validator.New()
	validate.RegisterValidation("passwd", validatePassword)
	if err := validate.Struct(userInput); err != nil {
		utils.ThrowErr(c, http.StatusBadRequest, "Password atleast using 1 number and 1 uppercase with minimum length 6 character")
		return
	}

	// compare password
	err = bcrypt.CompareHashAndPassword([]byte(reqUser.(models.UserModel).Password), []byte(userInput.PasswordNow))
	if err != nil {
		utils.ThrowErr(c, http.StatusUnauthorized, "Older password is wrong")
		return
	}

	newHashedPassword, err := bcrypt.GenerateFromPassword([]byte(userInput.PasswordNew), 16)
	if err != nil {
		utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
		return
	}

	// defer function tx & session
	defer func() {
		if (db_select == "sql") && (tx != nil) {
			if err != nil {
				_ = tx.Rollback()
			}
		} else if (db_select == "mongo") && (session != nil) {
			if err != nil {
				_ = session.AbortTransaction(c)
			}
			session.EndSession(c)
		}
	}()

	if db_select == "sql" {
		tx, err = db.DB.BeginTx(c, &sql.TxOptions{Isolation: sql.LevelSerializable})
		if err != nil {
			utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
			return
		}

		tx.Exec("UPDATE users SET password = $1 WHERE id = $2", newHashedPassword, reqUser.(models.UserModel).Id)

		if err = tx.Commit(); err != nil {
			utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
			return
		}

	} else {
		session, err := db.ClientM.StartSession()
		if err != nil {
			utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
			return
		}

		session.WithTransaction(c, func(ctx mongo.SessionContext) (interface{}, error) {
			id, err := primitive.ObjectIDFromHex(reqUser.(models.UserModel).Id)
			if err != nil {
				utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
				return nil, err
			}

			_, err = db.Collections.UserCollection.UpdateOne(c, bson.M{"_id": id}, bson.M{"$set": bson.M{"password": newHashedPassword}})
			if err != nil {
				utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
				return nil, err
			}

			if err = session.CommitTransaction(c); err != nil {
				utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
				return nil, err
			}

			return nil, nil
		})

	}

	c.JSON(http.StatusOK, gin.H{
		"errors":  false,
		"message": "User success change password",
	})
}

// TODO untested
func ChangeData(c *gin.Context) {
	db_select := utils.DBSelect(c)

	type ChangeDataUserInput struct {
		UserId string `json:"user_id"`
		Name   string `json:"name" binding:"required"`
		Role   *int   `json:"role"`
	}

	var user models.UserModel
	var tx *sql.Tx
	var session mongo.Session

	reqUser, exist := c.Get("user")
	if !exist {
		utils.ThrowErr(c, http.StatusUnauthorized, "Need Header Auth")
		return
	}

	var userInput ChangeDataUserInput

	err := c.ShouldBindJSON(&userInput)
	if err != nil {
		utils.ThrowErr(c, http.StatusBadRequest, err.Error())
		return
	}

	if reqUser.(models.UserModel).Role == 1 {
		userInput.UserId = reqUser.(models.UserModel).Id
	}

	if (reqUser.(models.UserModel).Role == 1) && (userInput.Role != nil) {
		utils.ThrowErr(c, http.StatusUnauthorized, "just admin can change role")
		return
	}

	defer func() {
		if (db_select == "sql") && (tx != nil) {
			if err != nil {
				_ = tx.Rollback()
			}
		} else if (db_select == "mongo") && (session != nil) {
			if err != nil {
				_ = session.AbortTransaction(c)
				session.EndSession(c)
			}
		}
	}()

	if db_select == "sql" {
		tx, err = db.DB.BeginTx(c, &sql.TxOptions{Isolation: sql.LevelSerializable})
		if err != nil {
			utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
			return
		}

		err = tx.QueryRow("SELECT id, username FROM users WHERE id = $1", userInput.UserId).Scan(&user.Id, &user.Username)
		if err != nil {
			if err == sql.ErrNoRows {
				utils.ThrowErr(c, http.StatusUnauthorized, "User Not Found")
			} else {
				utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
			}
			return
		}

		data := []interface{}{userInput.Name}
		paramIndex := 1
		query := fmt.Sprintf("UPDATE users SET name = $%d", paramIndex)

		if userInput.Role != nil {
			paramIndex++
			query += fmt.Sprintf(", role = $%d", paramIndex)
			data = append(data, userInput.Role)
		}

		paramIndex++
		query += fmt.Sprintf(" WHERE id = $%d", paramIndex)
		data = append(data, userInput.UserId)

		_, err := tx.Exec(query, data...)
		if err != nil {
			utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
			return
		}

		if err = tx.Commit(); err != nil {
			utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
			return
		}

	} else {
		session, err = db.ClientM.StartSession()
		if err != nil {
			utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
			return
		}

		session.WithTransaction(c, func(ctx mongo.SessionContext) (interface{}, error) {
			id, err := primitive.ObjectIDFromHex(userInput.UserId)
			if err != nil {
				utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
				return nil, err
			}

			err = db.Collections.UserCollection.FindOne(c, bson.M{"_id": id}).Decode(&user)
			if err != nil {
				if err == mongo.ErrNoDocuments {
					utils.ThrowErr(c, http.StatusUnauthorized, "User Not Found")
				} else {
					utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
				}
				return nil, err
			}

			update := bson.M{"name": userInput.Name}
			if userInput.Role != nil {
				update["role"] = userInput.Role
			}

			_, err = db.Collections.UserCollection.UpdateOne(c, bson.M{"_id": id}, bson.M{"$set": update})
			if err != nil {
				utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
				return nil, err
			}

			if err = session.CommitTransaction(c); err != nil {
				utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
				return nil, err
			}

			return nil, nil
		})

	}

	c.JSON(http.StatusOK, gin.H{
		"errors":  false,
		"message": "success change user data",
	})
}

// TODO untested
func ChangeStatus(c *gin.Context) {
	db_select := utils.DBSelect(c)

	type DataChangeStatus struct {
		Id string `json:"user_id" binding:"required"`
	}
	var dataUser DataChangeStatus
	var user models.UserModel
	var tx *sql.Tx
	var session mongo.Session

	reqUser, exist := c.Get("user")
	if !exist {
		utils.ThrowErr(c, http.StatusUnauthorized, "Need Header Auth")
		return
	}

	err := c.ShouldBindJSON(&dataUser)
	if err != nil {
		utils.ThrowErr(c, http.StatusBadRequest, err.Error())
		return
	}

	if dataUser.Id == reqUser.(models.UserModel).Id {
		utils.ThrowErr(c, http.StatusUnauthorized, "You can't change your own status")
		return
	}

	// defer function to rollback transaction if error
	defer func() {
		if (db_select == "sql") && (tx != nil) {
			if err != nil {
				_ = tx.Rollback()
			}
		} else if (db_select == "mongo") && (session != nil) {
			if err != nil {
				_ = session.AbortTransaction(c)
			}
			session.EndSession(c)
		}
	}()

	if db_select == "sql" {
		tx, err = db.DB.BeginTx(c, &sql.TxOptions{Isolation: sql.LevelSerializable})
		if err != nil {
			utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
			return
		}

		err = tx.QueryRow("SELECT id, username FROM users WHERE id = $1", dataUser.Id).Scan(&user.Id, &user.Username)
		if err != nil {
			if err == sql.ErrNoRows {
				utils.ThrowErr(c, http.StatusUnauthorized, "User Not Found")
			} else {
				utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
			}
			return
		}

		_, err = tx.Exec("UPDATE users SET is_active = NOT is_active WHERE id = $1", dataUser.Id)
		if err != nil {
			utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
			return
		}

		if err = tx.Commit(); err != nil {
			utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
			return
		}

	} else {
		session, err = db.ClientM.StartSession()
		if err != nil {
			utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
			return
		}

		// session.StartTransaction()
		session.WithTransaction(c, func(ctx mongo.SessionContext) (interface{}, error) {
			id, err := primitive.ObjectIDFromHex(dataUser.Id)
			if err != nil {
				utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
				c.Abort()
				return nil, err
			}

			err = db.Collections.UserCollection.FindOne(c, bson.M{"_id": id}).Decode(&user)
			if err != nil {
				if err == mongo.ErrNoDocuments {
					utils.ThrowErr(c, http.StatusUnauthorized, "User Not Found")
				} else {
					utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
				}
				return nil, err
			}

			_, err = db.Collections.UserCollection.UpdateOne(c, bson.M{"_id": id}, bson.M{"$set": bson.M{"is_active": !user.IsActive}})
			if err != nil {
				utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
				return nil, err
			}

			if err = session.CommitTransaction(c); err != nil {
				utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
				return nil, err
			}

			return nil, nil
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"errors":  false,
		"message": "success change status user",
	})
}

// TODO untested & undone
func DeleteUser(c *gin.Context) {
	db_select := utils.DBSelect(c)

	type DataDeleteUser struct {
		UserId string `json:"user_id" binding:"required"`
	}

	if db_select == "sql" {

	} else {

	}

	c.JSON(http.StatusOK, gin.H{
		"errors":  false,
		"message": "success delete user",
	})
}
