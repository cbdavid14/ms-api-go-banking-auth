package main

import (
	"github.com/cbdavid14/ms-api-go-banking-auth/app"
	"github.com/cbdavid14/ms-api-go-banking-auth/logger"
)

func main() {
	logger.Info("Starting the application...")
	app.Start()
}
