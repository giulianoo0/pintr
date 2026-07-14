package assets

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// presignURL builds an AWS SigV4 presigned GET URL for an object, signed for
// an explicit host. The S3 SDK can't presign against an R2 custom domain bound
// to a bucket (it always puts the bucket in the path or the subdomain), and the
// signature covers the Host header so the host can't be swapped after the fact —
// so we sign directly for the custom domain, with the object key as the path.
func presignURL(host, accessKey, secretKey, region, objectKey string, expires time.Duration, now time.Time) string {
	amzDate := now.UTC().Format("20060102T150405Z")
	dateStamp := now.UTC().Format("20060102")
	const service = "s3"
	scope := dateStamp + "/" + region + "/" + service + "/aws4_request"

	canonicalURI := "/" + awsURIEncode(objectKey, false) // keep the "/" between key segments

	query := map[string]string{
		"X-Amz-Algorithm":     "AWS4-HMAC-SHA256",
		"X-Amz-Credential":    accessKey + "/" + scope,
		"X-Amz-Date":          amzDate,
		"X-Amz-Expires":       strconv.Itoa(int(expires.Seconds())),
		"X-Amz-SignedHeaders": "host",
		"x-id":                "GetObject",
	}
	keys := make([]string, 0, len(query))
	for k := range query {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, awsURIEncode(k, true)+"="+awsURIEncode(query[k], true))
	}
	canonicalQuery := strings.Join(parts, "&")

	canonicalRequest := strings.Join([]string{
		"GET",
		canonicalURI,
		canonicalQuery,
		"host:" + host + "\n",
		"host",
		"UNSIGNED-PAYLOAD",
	}, "\n")

	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		scope,
		sha256Hex([]byte(canonicalRequest)),
	}, "\n")

	signingKey := hmacSHA256(
		hmacSHA256(
			hmacSHA256(
				hmacSHA256([]byte("AWS4"+secretKey), dateStamp),
				region),
			service),
		"aws4_request")
	signature := hex.EncodeToString(hmacSHA256(signingKey, stringToSign))

	return "https://" + host + canonicalURI + "?" + canonicalQuery + "&X-Amz-Signature=" + signature
}

// awsURIEncode percent-encodes per RFC 3986 as AWS SigV4 requires (uppercase
// hex, unreserved chars left as-is). When encodeSlash is false, "/" is kept for
// path segments.
func awsURIEncode(s string, encodeSlash bool) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9',
			c == '-', c == '_', c == '.', c == '~':
			b.WriteByte(c)
		case c == '/' && !encodeSlash:
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func hmacSHA256(key []byte, data string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(data))
	return mac.Sum(nil)
}
