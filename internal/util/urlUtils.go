package util

import "fmt"

func BuildURL(domain, endpoint, provider string) string {
	return fmt.Sprintf("https://%s/auth/%s/%s", domain, endpoint, provider)
}
