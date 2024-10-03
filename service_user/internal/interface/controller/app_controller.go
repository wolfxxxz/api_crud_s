package controller

type AppController struct {
	UserController interface{ UserController }
}
