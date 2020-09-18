package request

type DecryptRequest struct {
	EncryptedText string `json:"encrypted_text" binding:"required"`
}
