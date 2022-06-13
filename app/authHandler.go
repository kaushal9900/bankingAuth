package app

import (
	"bankingAuth/dto"
	"bankingAuth/service"
	"encoding/json"
	"net/http"

	"github.com/kaushal9900/banking-lib/logger"
)

type AuthHandler struct {
	service service.AuthService
}

func (h AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var loginRequest dto.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&loginRequest); err != nil {
		logger.Error("Error while Decoding login Request: " + err.Error())
		w.WriteHeader(http.StatusBadRequest)
	} else {
		token, appError := h.service.Login(loginRequest)
		if appError != nil {
			writeResponse(w, appError.Code, appError.AsMessage())
		} else {
			writeResponse(w, http.StatusOK, *token)
		}
	}

}

func writeResponse(w http.ResponseWriter, code int, data interface{}) {
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		panic(err)
	}
}
