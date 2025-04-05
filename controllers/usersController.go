package controllers

import (
	"docscheck-backend/initializers"
	"docscheck-backend/models"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

var (
	emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
)

func isValidEmail(email string) bool {
	return emailRegex.MatchString(email)
}

// SignUp godoc
// @Summary Register a new user
// @Description Create a new user account
// @Tags authentication
// @Accept json
// @Produce json
// @Param request body controllers.SignUpRequest true "User registration data"
// @Success 200 {object} controllers.SimpleResponse
// @Failure 400 {object} controllers.ErrorResponse
// @Failure 500 {object} controllers.ErrorResponse
// @Router /signup [post]
func SignUp(c *gin.Context) {
	var body struct {
		Email    string
		Password string
		Name     string
		PhotoUrl string
	}

	if err := c.Bind(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to read body"})
		return
	}

	// Обязательные поля
	if body.Email == "" || body.Password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Email and password are required"})
		return
	}

	// Валидация email
	if !isValidEmail(body.Email) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Please write a valid email"})
		return
	}

	// Валидация пароля
	if len(body.Password) < 8 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Password must be at least 8 characters"})
		return
	}

	// Хеширование пароля
	hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), 10)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}

	// Создание пользователя
	user := models.User{
		Email:    body.Email,
		Password: string(hash),
		PhotoUrl: &body.PhotoUrl,
		Name:     &body.Name,
	}

	result := initializers.DB.Create(&user)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "success"})
}

// Login godoc
// @Summary Authenticate user
// @Description Log in with email and password
// @Tags authentication
// @Accept json
// @Produce json
// @Param request body controllers.LoginRequest true "Credentials"
// @Success 200 {object} controllers.LoginResponse
// @Failure 400 {object} controllers.ErrorResponse
// @Failure 401 {object} controllers.ErrorResponse
// @Router /login [post]
func Login(c *gin.Context) {
	var body struct {
		Email    string
		Password string
	}

	if c.Bind(&body) != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to read body"})
		return
	}

	var user models.User
	initializers.DB.First(&user, "email = ?", body.Email)

	if user.ID == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid email or password"})
		return
	}

	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(body.Password))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid email or password"})
		return
	}

	// создание аксесс токена
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": user.ID,
		"exp": time.Now().Add(time.Minute * 15).Unix(),
	})
	accessTokenString, err := accessToken.SignedString([]byte(os.Getenv("ACCESS_SECRET")))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to sign access token"})
		return
	}

	// создание рефреш токена
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": user.ID,
		"exp": time.Now().Add(time.Hour * 24 * 7).Unix(),
	})
	refreshTokenString, err := refreshToken.SignedString([]byte(os.Getenv("REFRESH_SECRET")))

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to create refresh token"})
		return
	}

	// закинуть рефреш в дб
	user.RefreshToken = &refreshTokenString
	initializers.DB.Save(&user)

	// отправить рефреш в куки
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("RefreshToken", refreshTokenString, 3600*24*7, "", "", false, true)

	c.JSON(http.StatusOK, gin.H{
		"accessToken": accessTokenString,
	})
}

// Validate godoc
// @Summary Validate authentication
// @Description Check if user is authenticated
// @Tags authentication
// @Produce json
// @Security BearerAuth
// @Success 200 {object} models.User
// @Failure 401 {object} controllers.ErrorResponse
// @Router /validate [get]
// Объявляем структуру для безопасного ответа (без чувствительных данных)
type SafeUserResponse struct {
	ID        uint       `json:"ID"`
	CreatedAt time.Time  `json:"CreatedAt"`
	UpdatedAt time.Time  `json:"UpdatedAt"`
	DeletedAt *time.Time `json:"DeletedAt"`
	Email     string     `json:"Email"`
	PhotoUrl  string     `json:"PhotoUrl"`
	Name      string     `json:"Name"`
}

// Добавляем вспомогательную функцию для безопасного получения времени удаления
func getSafeDeletedAt(deletedAt gorm.DeletedAt) *time.Time {
	if deletedAt.Valid {
		return &deletedAt.Time
	}
	return nil
}

// Добавляем функцию для безопасного получения строки из указателя
func safeString(s *string) string {
	if s != nil {
		return *s
	}
	return ""
}

func Validate(c *gin.Context) {
	user, exists := c.Get("user")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found in context"})
		return
	}

	realUser, ok := user.(models.User)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid user type in context"})
		return
	}

	safeUser := SafeUserResponse{
		ID:        realUser.ID,
		CreatedAt: realUser.CreatedAt,
		UpdatedAt: realUser.UpdatedAt,
		DeletedAt: getSafeDeletedAt(realUser.DeletedAt), // Используем вспомогательную функцию
		Email:     realUser.Email,
		PhotoUrl:  safeString(realUser.PhotoUrl), // Используем безопасное получение строки
		Name:      safeString(realUser.Name),     // Используем безопасное получение строки
	}

	c.JSON(http.StatusOK, gin.H{
		"user": safeUser,
	})
}

// Refresh godoc
// @Summary Refresh access token
// @Description Get new access token using refresh token
// @Tags authentication
// @Produce json
// @Success 200 {object} controllers.LoginResponse
// @Failure 401 {object} controllers.ErrorResponse
// @Router /refresh [post]
func Refresh(c *gin.Context) {
	refreshTokenString, err := c.Cookie("RefreshToken")
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Refresh token required"})
		return
	}

	token, err := jwt.Parse(refreshTokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("REFRESH_SECRET")), nil
	})

	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid refresh token"})
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
		return
	}

	exp, ok := claims["exp"].(float64)
	if !ok || time.Now().Unix() > int64(exp) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Refresh token expired"})
		return
	}

	var user models.User
	sub := fmt.Sprint(claims["sub"])
	initializers.DB.First(&user, "id = ?", sub)

	if user.ID == 0 || *user.RefreshToken != refreshTokenString {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid refresh token"})
		return
	}

	// создать новый аксесс
	newAccessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": user.ID,
		"exp": time.Now().Add(time.Minute * 15).Unix(),
	})
	newAccessTokenString, err := newAccessToken.SignedString([]byte(os.Getenv("ACCESS_SECRET")))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to sign access token"})
		return
	}

	// и рефреш
	newRefreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": user.ID,
		"exp": time.Now().Add(time.Hour * 24 * 7).Unix(),
	})

	newRefreshTokenString, err := newRefreshToken.SignedString([]byte(os.Getenv("REFRESH_SECRET")))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to sign access token"})
		return
	}

	// закинуть рефреш в дб
	user.RefreshToken = &newRefreshTokenString
	initializers.DB.Save(&user)

	// закинуть в куки
	c.SetCookie("RefreshToken", newRefreshTokenString, 3600*24*7, "", "", false, true)

	c.JSON(http.StatusOK, gin.H{
		"accessToken": newAccessTokenString,
	})
}

// Logout godoc
// @Summary Log out user
// @Description Invalidate refresh token and clear cookies
// @Tags authentication
// @Produce json
// @Security BearerAuth
// @Success 200 {object} controllers.SimpleResponse
// @Failure 401 {object} controllers.ErrorResponse
// @Router /logout [post]
func Logout(c *gin.Context) {
	user, _ := c.Get("user")
	currentUser := user.(models.User)

	// убрать рефреш с дб
	currentUser.RefreshToken = nil
	initializers.DB.Save(&currentUser)

	// зачистить куки
	c.SetCookie("RefreshToken", "", -1, "", "", false, true)

	c.JSON(http.StatusOK, gin.H{
		"message": "Successfully logged out",
	})
}

// EditUser godoc
// @Summary Update user profile
// @Description Update user information
// @Tags users
// @Accept json
// @Produce json
// @Param id path string true "User ID"
// @Param request body controllers.EditUserRequest true "Update data"
// @Security BearerAuth
// @Success 200 {object} controllers.SimpleResponse
// @Failure 400 {object} controllers.ErrorResponse
// @Failure 403 {object} controllers.ErrorResponse
// @Failure 500 {object} controllers.ErrorResponse
// @Router /users/{id} [patch]
func EditUser(c *gin.Context) {
	// стянуть айди
	userID := c.Param("id")

	// стянуть пользователя с бд
	user, _ := c.Get("user")
	currentUser := user.(models.User)

	// перепроверить айдишник
	if fmt.Sprint(currentUser.ID) != userID {
		c.JSON(http.StatusForbidden, gin.H{"error": "You can only edit your own account"})
		return
	}

	// спарсить
	var body struct {
		Email    *string `json:"email"`
		Password *string `json:"password"`
		PhotoUrl *string `json:"photoUrl"`
		Name     *string `json:"name"`
	}

	if err := c.BindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}
	updates := make(map[string]interface{})

	// почта
	if body.Email != nil {
		if !isValidEmail(*body.Email) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid email format"})
			return
		}

		var existingUser models.User
		initializers.DB.Where("email = ?", *body.Email).First(&existingUser)
		if existingUser.ID != 0 && existingUser.ID != currentUser.ID {
			c.JSON(http.StatusConflict, gin.H{"error": "Email already in use"})
			return
		}
		updates["email"] = *body.Email
	}

	// пароль
	if body.Password != nil {
		hash, err := bcrypt.GenerateFromPassword([]byte(*body.Password), 10)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
			return
		}
		updates["password"] = string(hash)
	}

	// фото
	if body.PhotoUrl != nil {
		updates["photo_url"] = *body.PhotoUrl
	}

	// имя
	if body.Name != nil {
		updates["Name"] = *body.Name
	}

	// закинуть в бд
	result := initializers.DB.Model(&currentUser).Updates(updates)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User updated successfully"})
}

// DeleteUser godoc
// @Summary Delete user account
// @Description Permanently delete user account
// @Tags users
// @Produce json
// @Param id path string true "User ID"
// @Security BearerAuth
// @Success 200 {object} controllers.SimpleResponse
// @Failure 403 {object} controllers.ErrorResponse
// @Failure 500 {object} controllers.ErrorResponse
// @Router /users/{id} [delete]
func DeleteUser(c *gin.Context) {
	// стянуть айдишник
	userID := c.Param("id")

	// стянуть пользователя с бд
	user, _ := c.Get("user")
	currentUser := user.(models.User)

	// перепроверить айдишник
	if fmt.Sprint(currentUser.ID) != userID {
		c.JSON(http.StatusForbidden, gin.H{"error": "You can only delete your own account"})
		return
	}

	// удалить
	result := initializers.DB.Delete(&currentUser)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete user"})
		return
	}

	// рефреш куки убрать
	c.SetCookie("RefreshToken", "", -1, "", "", false, true)

	c.JSON(http.StatusOK, gin.H{"message": "User deleted successfully"})
}

type SignUpRequest struct {
	Email    string  `json:"email" example:"user@example.com"`
	Password string  `json:"password" example:"strongpassword123"`
	PhotoUrl *string `json:"photoUrl,omitempty" example:"https://example.com/photo.jpg"`
	Name     *string `json:"name,omitempty" example:"Инокентий Олегович"`
}

type LoginRequest struct {
	Email    string `json:"email" example:"user@example.com"`
	Password string `json:"password" example:"strongpassword123"`
}

type LoginResponse struct {
	AccessToken string `json:"accessToken" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."`
}

type EditUserRequest struct {
	Email    *string `json:"email,omitempty" example:"new.email@example.com"`
	Password *string `json:"password,omitempty" example:"newpassword123"`
	PhotoUrl *string `json:"photoUrl,omitempty" example:"https://example.com/new-photo.jpg"`
	Name     *string `json:"name,omitempty" example:"Новый Инокентий Олегович"`
}

type SimpleResponse struct {
	Message string `json:"message" example:"success"`
}

type ErrorResponse struct {
	Error string `json:"error" example:"error description"`
}
