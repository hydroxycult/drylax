package domain
import (
	"github.com/pkg/errors"
	"net/http"
)

var (
	ErrPasteNotFound      = NewErr("PASTE_NOT_FOUND", "paste not found", http.StatusNotFound)
	ErrPasteExpired       = NewErr("PASTE_EXPIRED", "paste expired", http.StatusNotFound)
	ErrPasteTooLarge      = NewErr("PASTE_TOO_LARGE", "paste too large", http.StatusBadRequest)
	ErrInvalidDuration    = NewErr("INVALID_DURATION", "invalid duration", http.StatusBadRequest)
	ErrPasswordRequired   = NewErr("PASSWORD_REQUIRED", "password required", http.StatusUnauthorized)
	ErrInvalidPassword    = NewErr("INVALID_PASSWORD", "invalid password", http.StatusUnauthorized)
	ErrInvalidRequest     = NewErr("INVALID_REQUEST", "invalid request", http.StatusBadRequest)
	ErrContentRequired    = NewErr("CONTENT_REQUIRED", "content required", http.StatusBadRequest)
	ErrRateLimitExceeded  = NewErr("RATE_LIMIT_EXCEEDED", "rate limit exceeded", http.StatusTooManyRequests)
	ErrUnauthorized       = NewErr("UNAUTHORIZED", "unauthorized", http.StatusUnauthorized)
	ErrInternalServer     = NewErr("INTERNAL_ERROR", "internal error", http.StatusInternalServerError)
	ErrIDGenerationFailed = NewErr("ID_GENERATION_FAILED", "id generation failed", http.StatusInternalServerError)
)
type Err struct {
	Code   string `json:"code"`
	Msg    string `json:"message"`
	Status int    `json:"-"`
}
func (e *Err) Error() string { return e.Msg }
func NewErr(code, msg string, status int) *Err {
	return &Err{Code: code, Msg: msg, Status: status}
}
type ErrResp struct {
	Error ErrDetail `json:"error"`
}
type ErrDetail struct {
	Code string                 `json:"code"`
	Msg  string                 `json:"message"`
	Meta map[string]interface{} `json:"meta,omitempty"`
}
func ToResp(err error) ErrResp {
	if e, ok := err.(*Err); ok {
		return ErrResp{Error: ErrDetail{Code: e.Code, Msg: e.Msg}}
	}
	if e, ok := errors.Cause(err).(*Err); ok {
		return ErrResp{Error: ErrDetail{Code: e.Code, Msg: e.Msg}}
	}
	return ErrResp{Error: ErrDetail{Code: "INTERNAL_ERROR", Msg: "internal error"}}
}
func Status(err error) int {
	if e, ok := err.(*Err); ok {
		return e.Status
	}
	if e, ok := errors.Cause(err).(*Err); ok {
		return e.Status
	}
	return http.StatusInternalServerError
}
