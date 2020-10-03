package request

type JWERequest struct {
	PublicKeyId string      `json:"public_key_id,omitempty" binding:"required"`
	Payload     interface{} `json:"payload,omitempty" binding:"required"`
}
