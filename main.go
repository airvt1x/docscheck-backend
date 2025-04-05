package main

import (
	"docscheck-backend/controllers"
	_ "docscheck-backend/docs"
	"docscheck-backend/initializers"
	"docscheck-backend/middleware"

	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"

	"github.com/gin-gonic/gin"
)

func init() {
	initializers.LoadEnvVariables()
	initializers.ConnectToDb()
	initializers.SyncDatabase()
}

// @title DocsCheck backend API
// @version 1.0
// @description API for user authentication and management
// @securityDefinitions.apikey BearerAuth
// @in header
// @name API keys
// @host localhost:3000
// @BasePath /
func main() {
	r := gin.Default()

	r.POST("/signup", controllers.SignUp)
	r.POST("/login", controllers.Login)
	r.POST("/refresh", controllers.Refresh)
	r.POST("/logout", middleware.RequireAuth, controllers.Logout)
	r.GET("/validate", middleware.RequireAuth, controllers.Validate)
	r.PATCH("/users/:id", middleware.RequireAuth, controllers.EditUser)
	r.DELETE("/users/:id", middleware.RequireAuth, controllers.DeleteUser)

	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	r.Run()
}
