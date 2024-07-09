package controllers

import (
	"context"
	"database/sql"
	"errors"
	"math/rand"
	"net/http"
	"regexp"
	"strconv"
	"ta-url-shortener-go/db"
	"ta-url-shortener-go/models"
	"ta-url-shortener-go/utils"
	"time"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// * ------------------ FUNCTION
func GenerateRandomString(length int) string {
	const char = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	var randomStr = make([]byte, length)

	// Seed the random number generator to get different results each time
	rand.Seed(time.Now().UnixNano())

	for i := range randomStr {
		randomStr[i] = char[rand.Intn(len(char))]
	}

	return string(randomStr)
}

// * ------------------ CONTROLLER
func GetLinkMain(c *gin.Context) {
	var linkRes models.LinkModel

	db_select := utils.DBSelect(c)

	short_link := c.Params.ByName("short_link")

	if db_select == "sql" {
		row := db.DB.QueryRow("SELECT long_link, short_link FROM urls WHERE short_link = $1", short_link)

		err := row.Scan(&linkRes.LongLink, &linkRes.ShortLink)
		if err != nil {
			if err == sql.ErrNoRows {
				utils.ThrowErr(c, http.StatusNotFound, "short link not found")
			} else {
				utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
			}
			return
		}

		_, err = db.DB.Exec("UPDATE urls SET total_visited = total_visited + 1, last_visited = NOW() WHERE short_link = $1", short_link)
		if err != nil {
			utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
			return
		}

	} else {
		err := db.Collections.LinkCollection.FindOne(context.TODO(), bson.M{"short_link": short_link}).Decode(&linkRes)
		if err != nil {
			if err == mongo.ErrNoDocuments {
				utils.ThrowErr(c, http.StatusUnauthorized, "short link Not Found")
			} else {
				utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
			}
			return
		}

		_, err = db.Collections.LinkCollection.UpdateOne(context.TODO(), bson.M{"short_link": short_link}, bson.M{"$set": bson.M{"total_visited": linkRes.TotalVisited + 1, "last_visited": time.Now()}})
		if err != nil {
			utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"errors":  false,
		"message": "short link found",
		"data": gin.H{
			"long_url":  linkRes.LongLink,
			"short_url": linkRes.ShortLink,
		},
	})
}

func GetAllLinks(c *gin.Context) {
	db_select := utils.DBSelect(c)

	type linkRes struct {
		Id           string              `json:"id" bson:"_id"`
		ShortLink    string              `json:"short_link" bson:"short_link"`
		LongLink     string              `json:"long_link" bson:"long_link"`
		LastVisited  time.Time           `json:"last_visited" bson:"last_visited"`
		TotalVisited int                 `json:"total_visited" bson:"total_visited"`
		CreatedAt    time.Time           `json:"created_at" bson:"created_at"`
		UpdatedAt    time.Time           `json:"updated_at" bson:"updated_at"`
		User         models.UserModelRes `json:"user" bson:"user"`
	}
	var links []linkRes
	var total_links int

	// * pagination
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	size, _ := strconv.Atoi(c.DefaultQuery("per_page", "10"))
	offset := (page - 1) * size
	search := c.DefaultQuery("search", "")

	if db_select == "sql" {
		query := "SELECT a.id, a.user_id, b.username, b.name, b.role, b.is_active, a.long_link, a.short_link, a.last_visited, a.total_visited, a.created_at, a.updated_at FROM urls a left join users b on a.user_id = b.id where 1=1"

		if search != "" {
			query += " AND (short_link ILIKE '%" + search + "%' OR long_link ILIKE '%" + search + "%')"
		}

		if err := db.DB.QueryRow("select count (*) from (" + query + ") as total").Scan(&total_links); err != nil {
			utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
			return
		}

		if userRow, err := db.DB.Query(query+" ORDER BY a.id DESC LIMIT $1 OFFSET $2", size, offset); err != nil {
			utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
			return
		} else {
			defer userRow.Close()
			for userRow.Next() {
				var timeSql sql.NullTime
				var link linkRes
				if err := userRow.Scan(&link.Id, &link.User.Id, &link.User.Username, &link.User.Name, &link.User.Role, &link.User.IsActive, &link.LongLink, &link.ShortLink, &timeSql, &link.TotalVisited, &link.CreatedAt, &link.UpdatedAt); err != nil {
					utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
					return
				}

				if timeSql.Valid {
					link.LastVisited = timeSql.Time
				}

				links = append(links, link)
			}
		}

	} else {
		query := bson.M{}
		if search != "" {
			query["$or"] = []bson.M{
				{"short_link": bson.M{"$regex": search, "$options": "i"}},
				{"long_link": bson.M{"$regex": search, "$options": "i"}},
			}
		}

		if total, err := db.Collections.LinkCollection.CountDocuments(c, query); err != nil {
			utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
			return
		} else {
			total_links = int(total)
		}

		size64 := int64(size)
		offset64 := int64(offset)
		if linkRows, err := db.Collections.LinkCollection.Find(c, query, &options.FindOptions{
			Skip:  &offset64,
			Limit: &size64,
		}); err != nil {
			utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
			return
		} else {
			defer linkRows.Close(c)
			for linkRows.Next(c) {
				var linkTemp models.LinkModelResAll
				var link linkRes
				if err := linkRows.Decode(&linkTemp); err != nil {
					utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
					return
				}

				link = linkRes{
					Id:           linkTemp.Id,
					ShortLink:    linkTemp.ShortLink,
					LongLink:     linkTemp.LongLink,
					TotalVisited: linkTemp.TotalVisited,
					LastVisited:  linkTemp.LastVisited,
					CreatedAt:    linkTemp.CreatedAt,
					UpdatedAt:    linkTemp.UpdatedAt,
				}

				id, err := primitive.ObjectIDFromHex(linkTemp.UserId)
				if err != nil {
					utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
					return
				}

				if err := db.Collections.UserCollection.FindOne(c, bson.M{"_id": id}).Decode(&link.User); err != nil {
					utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
					return
				}

				links = append(links, link)
			}
		}
	}

	if links == nil {
		links = []linkRes{}
	}

	c.JSON(http.StatusOK, gin.H{
		"errors":  false,
		"message": "info link data",
		"data": gin.H{
			"page":       page,
			"per_page":   size,
			"total_data": total_links,
			"links":      links,
		},
	})
}

func GetLinkSelf(c *gin.Context) {
	db_select := utils.DBSelect(c)

	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	size, _ := strconv.Atoi(c.DefaultQuery("per_page", "10"))
	offset := (page - 1) * size
	search := c.DefaultQuery("search", "")

	var links []models.LinkModelRes
	var total_links int

	reqUser, exist := c.Get("user")
	if !exist {
		utils.ThrowErr(c, http.StatusInternalServerError, "user not found")
		return
	}

	if db_select == "sql" {
		query := "SELECT a.id, a.user_id, a.long_link, a.short_link, a.last_visited, a.total_visited, a.created_at, a.updated_at FROM urls a WHERE user_id = $1"

		if search != "" {
			query += " AND (short_link ILIKE '%" + search + "%' OR long_link ILIKE '%" + search + "%') "
		}

		if err := db.DB.QueryRow("select count (*) from ("+query+") as total", reqUser.(models.UserModel).Id).Scan(&total_links); err != nil {
			utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
			return
		}

		if linkRows, err := db.DB.Query(query+" ORDER BY a.id DESC LIMIT $2 OFFSET $3", reqUser.(models.UserModel).Id, size, offset); err != nil {
			utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
			return
		} else {
			defer linkRows.Close()
			for linkRows.Next() {
				var timeSql sql.NullTime
				var link models.LinkModelRes
				if err := linkRows.Scan(&link.Id, &link.UserId, &link.LongLink, &link.ShortLink, &timeSql, &link.TotalVisited, &link.CreatedAt, &link.UpdatedAt); err != nil {
					utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
					return
				}

				if timeSql.Valid {
					link.LastVisited = timeSql.Time
				}

				links = append(links, link)
			}
		}

	} else {
		id, err := primitive.ObjectIDFromHex(reqUser.(models.UserModel).Id)
		if err != nil {
			utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
			return
		}

		query := bson.M{
			"user_id": id,
		}
		if search != "" {
			query["$or"] = []bson.M{
				{"short_link": bson.M{"$regex": search, "$options": "i"}},
				{"long_link": bson.M{"$regex": search, "$options": "i"}},
			}
		}

		total, err := db.Collections.LinkCollection.CountDocuments(c, query)
		if err != nil {
			utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
			return
		}
		total_links = int(total)

		size64 := int64(size)
		offset64 := int64(offset)
		if linkRows, err := db.Collections.LinkCollection.Find(c, query, &options.FindOptions{
			Skip:  &offset64,
			Limit: &size64,
		}); err != nil {
			utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
		} else {
			if err = linkRows.All(c, &links); err != nil {
				utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
				return
			}
		}
	}

	if links == nil {
		links = []models.LinkModelRes{}
	}

	c.JSON(http.StatusOK, gin.H{
		"errors":  false,
		"message": "info link data",
		"data": gin.H{
			"page":       page,
			"per_page":   size,
			"total_data": total_links,
			"links":      links,
		},
	})
}

func GetOneLink(c *gin.Context) {
	db_select := utils.DBSelect(c)

	url_id := c.Params.ByName("id")

	var linkRes models.LinkModelResAll
	var linkResHistory []models.LinkHistoryModel

	reqUser, exist := c.Get("user")
	if !exist {
		utils.ThrowErr(c, http.StatusInternalServerError, "user not found")
		return
	}

	if db_select == "sql" {
		var timeSql sql.NullTime
		if err := db.DB.QueryRow("SELECT a.id, a.user_id, b.username, b.name, b.role, b.is_active, a.long_link, a.short_link, a.last_visited, a.total_visited, a.created_at, a.updated_at FROM urls a left join users b on a.user_id = b.id where a.id = $1", url_id).Scan(&linkRes.Id, &linkRes.UserId, &linkRes.User.Username, &linkRes.User.Name, &linkRes.User.Role, &linkRes.User.IsActive, &linkRes.LongLink, &linkRes.ShortLink, &timeSql, &linkRes.TotalVisited, &linkRes.CreatedAt, &linkRes.UpdatedAt); err != nil {
			if err == sql.ErrNoRows {
				utils.ThrowErr(c, http.StatusNotFound, "link not found")
			} else {
				utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
			}
			return
		}

		if timeSql.Valid {
			linkRes.LastVisited = timeSql.Time
		}

		linkRes.User.Id = linkRes.UserId

		//if not admin, only can see own link
		if (reqUser.(models.UserModel).Id != linkRes.UserId) && (reqUser.(models.UserModel).Role != 1) {
			utils.ThrowErr(c, http.StatusUnauthorized, "you are not authorized to see this link")
			return
		}

		if linkHistoryRows, err := db.DB.Query("SELECT id, url_id, long_link, short_link, user_id, total_visited, created_at FROM urls_history WHERE url_id = $1 order by created_at asc", url_id); err != nil {
			utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
			return
		} else {
			for linkHistoryRows.Next() {
				var linkHistory models.LinkHistoryModel
				if err := linkHistoryRows.Scan(&linkHistory.Id, &linkHistory.UrlId, &linkHistory.LongLink, &linkHistory.ShortLink, &linkHistory.UserId, &linkHistory.TotalVisited, &linkHistory.CreatedAt); err != nil {
					utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
					return
				}

				linkResHistory = append(linkResHistory, linkHistory)
			}
		}

	} else {
		id, err := primitive.ObjectIDFromHex(url_id)
		if err != nil {
			utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
			return
		}

		if err := db.Collections.LinkCollection.FindOne(c, bson.M{"_id": id}).Decode(&linkRes); err != nil {
			if err == mongo.ErrNoDocuments {
				utils.ThrowErr(c, http.StatusNotFound, "link not found")
			} else {
				utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
			}
			return
		}

		idUser, err := primitive.ObjectIDFromHex(linkRes.UserId)
		if err != nil {
			utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
			return
		}

		if err := db.Collections.UserCollection.FindOne(c, bson.M{"_id": idUser}).Decode(&linkRes.User); err != nil {
			utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
			return
		}

		linkRes.User.Id = linkRes.UserId

		if (reqUser.(models.UserModel).Id != linkRes.UserId) && (reqUser.(models.UserModel).Role != 1) {
			utils.ThrowErr(c, http.StatusUnauthorized, "you are not authorized to see this link")
			return
		}

		linkHistory, err := db.Collections.LinkHistoryCollection.Find(c, bson.M{"url_id": url_id})
		if err != nil {
			utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
			return
		}

		err = linkHistory.All(context.TODO(), &linkResHistory)
		if err != nil {
			utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
			return
		}
	}

	if linkResHistory == nil {
		linkResHistory = []models.LinkHistoryModel{}
	}

	dataRes := gin.H{
		"id":            linkRes.Id,
		"short_link":    linkRes.ShortLink,
		"long_link":     linkRes.LongLink,
		"last_visited":  linkRes.LastVisited,
		"total_visited": linkRes.TotalVisited,
		"created_at":    linkRes.CreatedAt,
		"updated_at":    linkRes.UpdatedAt,
		"user": gin.H{
			"id":        linkRes.User.Id,
			"username":  linkRes.User.Username,
			"name":      linkRes.User.Name,
			"role":      linkRes.User.Role,
			"is_active": linkRes.User.IsActive,
		},
		"history": linkResHistory,
	}

	c.JSON(http.StatusOK, gin.H{
		"errors":  false,
		"message": "get one link data",
		"data":    dataRes,
	})
}

func CreateLink(c *gin.Context) {
	db_select := utils.DBSelect(c)

	type inputNewLink struct {
		LongUrl  string  `json:"long_url" binding:"required"`
		ShortUrl *string `json:"short_url"`
		IsCustom *bool   `json:"custom_link"`
	}

	var tx *sql.Tx
	var session mongo.Session
	var dataNewLink inputNewLink
	var newShortLink string
	var returnId string
	var linkCheck string

	err := c.ShouldBindJSON(&dataNewLink)
	if err != nil {
		utils.ThrowErr(c, http.StatusBadRequest, "input data must included long_url as string and short_url as string with minimum 5 character alphanumeric")
		return
	}

	if dataNewLink.IsCustom == nil {
		*dataNewLink.IsCustom = false
	}

	if (dataNewLink.ShortUrl == nil) && (*dataNewLink.IsCustom) {
		utils.ThrowErr(c, http.StatusBadRequest, "short_url must be included if custom_link is true or not included")
		return
	}

	if dataNewLink.ShortUrl != nil {
		is_alphanumeric := regexp.MustCompile(`^[a-zA-Z0-9]*$`).MatchString(*dataNewLink.ShortUrl)
		if (!is_alphanumeric) || (len(*dataNewLink.ShortUrl) < 5) {
			utils.ThrowErr(c, http.StatusBadRequest, "short_url must be alphanumeric with minimum 5 character")
			return
		}
	}

	reqUser, exist := c.Get("user")
	if !exist {
		utils.ThrowErr(c, http.StatusInternalServerError, "user not found")
		return
	}

	defer func() {
		if (db_select == "sql") && (tx != nil) {
			if err != nil {
				_ = tx.Rollback()
			}
		} else if (db_select == "mongo") && (session != nil) {
			if err != nil {
				_ = session.AbortTransaction((c))
			}
			session.EndSession(c)
		}
	}()

	if db_select == "sql" {
		var returnNewId int

		tx, err = db.DB.BeginTx(c, &sql.TxOptions{})
		if err != nil {
			utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
			return
		}

		if !(*dataNewLink.IsCustom) {
			isExist := true
			for isExist {
				newShortLink = GenerateRandomString(7)

				err = tx.QueryRow("SELECT short_link FROM urls WHERE short_link = $1", newShortLink).Scan(&linkCheck)
				if (err != nil) && (err != sql.ErrNoRows) {
					utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
					return
				}

				if err == sql.ErrNoRows {
					isExist = false
				}
			}

		} else {
			newShortLink = *dataNewLink.ShortUrl

			err = tx.QueryRow("SELECT short_link FROM urls WHERE short_link = $1", newShortLink).Scan(&linkCheck)

			if (err != nil) && (err != sql.ErrNoRows) {
				utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
				return
			}

			if !(err == sql.ErrNoRows) {
				utils.ThrowErr(c, http.StatusBadRequest, "Custom link already exist")
				return
			}
		}

		if err = tx.QueryRow("INSERT INTO urls (long_link, short_link, user_id) VALUES ($1, $2, $3) RETURNING id", dataNewLink.LongUrl, newShortLink, reqUser.(models.UserModel).Id).Scan(&returnNewId); err != nil {
			utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
			return
		}

		returnId = strconv.Itoa(returnNewId)

		if err = tx.Commit(); err != nil {
			utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
			return
		}

	} else {
		var linkCheck models.LinkModel

		session, err = db.ClientM.StartSession()
		if err != nil {
			utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
			return
		}

		err = mongo.WithSession(c, session, func(sessionContext mongo.SessionContext) error {
			if err = session.StartTransaction(); err != nil {
				return err
			}

			if !(*dataNewLink.IsCustom) {
				isExist := true
				for isExist {
					newShortLink = GenerateRandomString(7)

					err := db.Collections.LinkCollection.FindOne(sessionContext, bson.M{"short_link": newShortLink}).Decode(&linkCheck)
					if (err != nil) && (err != mongo.ErrNoDocuments) {
						return err
					}

					if err == mongo.ErrNoDocuments {
						isExist = false
					}
				}

			} else {
				newShortLink = *dataNewLink.ShortUrl

				err := db.Collections.LinkCollection.FindOne(sessionContext, bson.M{"short_link": newShortLink}).Decode(&linkCheck)
				if (err != nil) && (err != mongo.ErrNoDocuments) {
					return err
				}

				if !(err == mongo.ErrNoDocuments) {
					return errors.New("Custom link already exist")
				}
			}

			timeNow := time.Now()
			userId, err := primitive.ObjectIDFromHex(reqUser.(models.UserModel).Id)
			if err != nil {
				return err
			}
			result, err := db.Collections.LinkCollection.InsertOne(sessionContext, bson.M{
				"long_link":     dataNewLink.LongUrl,
				"short_link":    newShortLink,
				"user_id":       userId,
				"total_visited": 0,
				"last_visited":  nil,
				"created_at":    timeNow,
				"updated_at":    timeNow,
			})
			if err != nil {
				return err
			}

			returnId = result.InsertedID.(primitive.ObjectID).Hex()

			if err := session.CommitTransaction(sessionContext); err != nil {
				return err
			}

			return nil
		})
		if err != nil {
			utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
			return
		}

	}

	c.JSON(http.StatusOK, gin.H{
		"errors":  false,
		"message": "Successfully created short link",
		"data": gin.H{
			"long_url":    dataNewLink.LongUrl,
			"short_url":   newShortLink,
			"inserted_id": returnId,
		},
	})
}

func EditLink(c *gin.Context) {
	db_select := utils.DBSelect(c)

	type EditLinkInput struct {
		UrlId    string  `json:"url_id" binding:"required"`
		LongUrl  string  `json:"long_url" binding:"required"`
		ShortUrl *string `json:"short_url"`
		IsCustom *bool   `json:"custom_link"`
	}

	var tx *sql.Tx
	var session mongo.Session
	var editUserInput EditLinkInput
	var LinkCheck models.LinkModel
	var newShortLink string
	timeNow := time.Now()
	newTotalVisited := 0

	err := c.ShouldBindJSON(&editUserInput)
	if err != nil {
		utils.ThrowErr(c, http.StatusBadRequest, "input data must included url_id as string, long_url as string and short_url as string with minimum 5 character alphanumeric")
		return
	}

	if editUserInput.IsCustom == nil {
		*editUserInput.IsCustom = false
	}

	if (editUserInput.ShortUrl == nil) && (*editUserInput.IsCustom) {
		utils.ThrowErr(c, http.StatusBadRequest, "short_url must be included if custom_link is true or not included")
		return
	}

	if editUserInput.ShortUrl != nil {
		is_alphanumeric := regexp.MustCompile(`^[a-zA-Z0-9]*$`).MatchString(*editUserInput.ShortUrl)
		if (!is_alphanumeric) || (len(*editUserInput.ShortUrl) < 5) {
			utils.ThrowErr(c, http.StatusBadRequest, "short_url must be alphanumeric with minimum 5 character")
			return
		}
	}

	reqUser, exist := c.Get("user")
	if !exist {
		utils.ThrowErr(c, http.StatusInternalServerError, "user not found")
		return
	}

	defer func() {
		if (db_select == "sql") && (tx != nil) {
			if err != nil {
				_ = tx.Rollback()
			}
		} else if (db_select == "mongo") && (session != nil) {
			if err != nil {
				_ = session.AbortTransaction((c))
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

		if err = tx.QueryRow("select id, long_link, short_link, user_id, total_visited from urls where id = $1", editUserInput.UrlId).Scan(&LinkCheck.Id, &LinkCheck.LongLink, &LinkCheck.ShortLink, &LinkCheck.UserId, &LinkCheck.TotalVisited); err != nil {
			if err == sql.ErrNoRows {
				utils.ThrowErr(c, http.StatusNotFound, "link not found")
			} else {
				utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
			}
			return
		} else {
			if LinkCheck.UserId != reqUser.(models.UserModel).Id {
				utils.ThrowErr(c, http.StatusUnauthorized, "you are not authorized to edit this link")
				return
			}
		}

		if !(*editUserInput.IsCustom) {
			isExist := true
			for isExist {
				newShortLink = GenerateRandomString(7)

				err = tx.QueryRow("SELECT short_link FROM urls WHERE short_link = $1", newShortLink).Scan(&LinkCheck.ShortLink)
				if (err != nil) && (err != sql.ErrNoRows) {
					utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
					return
				}

				if err == sql.ErrNoRows {
					isExist = false
				}
			}

		} else {
			newShortLink = *editUserInput.ShortUrl

			err = tx.QueryRow("SELECT id, short_link FROM urls WHERE short_link = $1", newShortLink).Scan(&LinkCheck.Id, &LinkCheck.ShortLink)
			if (err != nil) && (err != sql.ErrNoRows) {
				utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
				return
			}

			if !(err == sql.ErrNoRows) {
				if LinkCheck.Id != editUserInput.UrlId {
					utils.ThrowErr(c, http.StatusBadRequest, "Custom link already exist")
					return
				}
			}
		}

		if _, err := tx.Exec("UPDATE urls SET long_link = $1, short_link = $2, updated_at = $3, total_visited = $4 WHERE id = $5", editUserInput.LongUrl, newShortLink, timeNow, newTotalVisited, editUserInput.UrlId); err != nil {

			utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
			return
		} else {

			if _, err := tx.Exec("INSERT INTO urls_history (long_link, short_link, user_id, total_visited, url_id) VALUES ($1, $2, $3, $4, $5)", LinkCheck.LongLink, LinkCheck.ShortLink, LinkCheck.UserId, LinkCheck.TotalVisited, LinkCheck.Id); err != nil {
				utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
				return
			}

			if err := tx.Commit(); err != nil {
				utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
				return
			}
		}

	} else {
		session, err = db.ClientM.StartSession()
		if err != nil {
			utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
			return
		}

		if err = mongo.WithSession(c, session, func(sessionContext mongo.SessionContext) error {
			if err = session.StartTransaction(); err != nil {
				return err
			}

			id, err := primitive.ObjectIDFromHex(editUserInput.UrlId)
			if err != nil {
				return err
			}

			if err = db.Collections.LinkCollection.FindOne(sessionContext, bson.M{"_id": id}).Decode(&LinkCheck); err != nil {
				if err == mongo.ErrNoDocuments {
					return errors.New("link not found")
				}
				return err
			} else {
				if LinkCheck.UserId != reqUser.(models.UserModel).Id {
					return errors.New("you are not authorized to edit this link")
				}
			}

			if !(*editUserInput.IsCustom) {
				isExist := true
				for isExist {
					newShortLink = GenerateRandomString(7)

					err = db.Collections.LinkCollection.FindOne(sessionContext, bson.M{"short_link": newShortLink}).Decode(&LinkCheck)
					if (err != nil) && (err != mongo.ErrNoDocuments) {
						return err
					}

					if err == mongo.ErrNoDocuments {
						isExist = false
					}
				}

			} else {
				newShortLink = *editUserInput.ShortUrl

				err = db.Collections.LinkCollection.FindOne(sessionContext, bson.M{"short_link": newShortLink}).Decode(&LinkCheck)
				if (err != nil) && (err != mongo.ErrNoDocuments) {
					return err
				}

				if !(err == mongo.ErrNoDocuments) {
					if LinkCheck.Id != editUserInput.UrlId {
						return errors.New("Custom link already exist")
					}
				}
			}

			if _, err = db.Collections.LinkCollection.UpdateOne(sessionContext, bson.M{"_id": id}, bson.M{"$set": bson.M{
				"long_link":     editUserInput.LongUrl,
				"short_link":    newShortLink,
				"updated_at":    timeNow,
				"total_visited": newTotalVisited,
			}}); err != nil {
				return err
			} else {
				if _, err = db.Collections.LinkHistoryCollection.InsertOne(sessionContext, bson.M{
					"url_id":        LinkCheck.Id,
					"user_id":       LinkCheck.UserId,
					"long_link":     LinkCheck.LongLink,
					"short_link":    LinkCheck.ShortLink,
					"total_visited": LinkCheck.TotalVisited,
					"created_at":    time.Now(),
				}); err != nil {
					return err
				}
			}

			if err = session.CommitTransaction(sessionContext); err != nil {
				return err
			}

			return nil
		}); err != nil {
			utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"errors":  false,
		"message": "success update url data",
		"data": gin.H{
			"long_url":  editUserInput.LongUrl,
			"short_url": newShortLink,
		},
	})
}

func DeleteLink(c *gin.Context) {
	db_select := utils.DBSelect(c)

	type DeleteLinkInput struct {
		UrlId string `json:"url_id" binding:"required"`
	}

	var tx *sql.Tx
	var session mongo.Session
	var deleteInput DeleteLinkInput
	var LinkCheck models.LinkModel

	reqUser, exist := c.Get("user")
	if !exist {
		utils.ThrowErr(c, http.StatusInternalServerError, "user not found")
		return
	}

	err := c.ShouldBindJSON(&deleteInput)
	if err != nil {
		utils.ThrowErr(c, http.StatusBadRequest, "input data must included url_id as string")
		return
	}

	defer func() {
		if (db_select == "sql") && (tx != nil) {
			if err != nil {
				_ = tx.Rollback()
			}
		} else if (db_select == "mongo") && (session != nil) {
			if err != nil {
				_ = session.AbortTransaction((c))
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

		if err := tx.QueryRow("select id, long_link, short_link, user_id, total_visited from urls where id = $1", deleteInput.UrlId).Scan(&LinkCheck.Id, &LinkCheck.LongLink, &LinkCheck.ShortLink, &LinkCheck.UserId, &LinkCheck.TotalVisited); err != nil {
			if err == sql.ErrNoRows {
				utils.ThrowErr(c, http.StatusNotFound, "link not found")
			} else {
				utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
			}
			return
		} else {
			if (LinkCheck.UserId != reqUser.(models.UserModel).Id) && (reqUser.(models.UserModel).Role != 1) {
				utils.ThrowErr(c, http.StatusUnauthorized, "you are not authorized to delete this link")
				return
			}
		}

		if _, err := tx.Exec("DELETE FROM urls WHERE id = $1", deleteInput.UrlId); err != nil {
			utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
			return
		} else {
			if _, err := tx.Exec("INSERT INTO urls_history (long_link, short_link, user_id, total_visited, url_id) VALUES ($1, $2, $3, $4, $5)", LinkCheck.LongLink, LinkCheck.ShortLink, LinkCheck.UserId, LinkCheck.TotalVisited, LinkCheck.Id); err != nil {
				utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
				return
			}

			if err := tx.Commit(); err != nil {
				utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
				return
			}
		}

	} else {
		session, err = db.ClientM.StartSession()
		if err != nil {
			utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
			return
		}

		if err = mongo.WithSession(c, session, func(sessionContext mongo.SessionContext) error {
			if err = session.StartTransaction(); err != nil {
				return err
			}

			id, err := primitive.ObjectIDFromHex(deleteInput.UrlId)
			if err != nil {
				return err
			}

			if err = db.Collections.LinkCollection.FindOne(sessionContext, bson.M{"_id": id}).Decode(&LinkCheck); err != nil {
				if err == mongo.ErrNoDocuments {
					return errors.New("link not found")
				}
				return err
			} else {
				if (LinkCheck.UserId != reqUser.(models.UserModel).Id) && (reqUser.(models.UserModel).Role != 1) {
					return errors.New("you are not authorized to delete this link")
				}
			}

			if _, err = db.Collections.LinkCollection.DeleteOne(sessionContext, bson.M{"_id": id}); err != nil {
				return err
			} else {
				if _, err = db.Collections.LinkHistoryCollection.InsertOne(sessionContext, bson.M{
					"url_id":        LinkCheck.Id,
					"user_id":       LinkCheck.UserId,
					"long_link":     LinkCheck.LongLink,
					"short_link":    LinkCheck.ShortLink,
					"total_visited": LinkCheck.TotalVisited,
					"created_at":    time.Now(),
				}); err != nil {
					return err
				}

				if err = session.CommitTransaction(sessionContext); err != nil {
					return err
				}
			}

			return nil
		}); err != nil {
			utils.ThrowErr(c, http.StatusInternalServerError, err.Error())
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"errors":  false,
		"message": "success delete url data",
	})
}
