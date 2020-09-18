package init

import "crypto-service/docs"

func Swagger() {
	docs.SwaggerInfo.Title = "Swagger CRYPTO-SERVICE API"
	docs.SwaggerInfo.Description = "This is Gola CRYPTO API Server"
	docs.SwaggerInfo.Version = "1.0"
	docs.SwaggerInfo.Host = ""
	docs.SwaggerInfo.BasePath = ""
	docs.SwaggerInfo.Schemes = []string{"https", "http"}
}
