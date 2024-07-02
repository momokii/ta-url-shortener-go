package utils

import (
	"github.com/gin-gonic/gin"
)

func DBSelect(c *gin.Context) string {
	db_select := c.Query("db")
	if db_select == "" {
		db_select = "sql"
	}
	if db_select == "sql" {
		db_select = "sql"
	} else {
		db_select = "mongo"
	}

	return db_select
}
