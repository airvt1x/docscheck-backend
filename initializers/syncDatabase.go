package initializers

import "docscheck-backend/models"

func SyncDatabase() {
	DB.AutoMigrate(&models.User{})
}
