package banner

import (
	"os"
	"strings"
)

const Unicode = `                                                       ███
                                                     ░░░
  ██████   ████████   █████ ████  ██████   ████████  ████
 ░░░░░███ ░░███░░███ ░░███ ░███  ░░░░░███ ░░███░░███░░███
  ███████  ░███ ░███  ░███ ░███   ███████  ░███ ░███ ░███
 ███░░███  ░███ ░███  ░███ ░███  ███░░███  ░███ ░███ ░███
░░████████ ████ █████ ░░███████  ░░████████ ░███████  █████
 ░░░░░░░░ ░░░░ ░░░░░   ░░░░░███  ░░░░░░░░  ░███░░░  ░░░░░
                       ███ ░███               ░███
                      ░░██████                █████
                       ░░░░░░                ░░░░░`

const Plain = `anyapi
local API-to-CLI compiler`

func Text() string {
	if strings.EqualFold(os.Getenv("ANYAPI_BANNER"), "plain") || strings.EqualFold(os.Getenv("TERM"), "dumb") {
		return Plain
	}
	locale := os.Getenv("LC_ALL")
	if locale == "" {
		locale = os.Getenv("LC_CTYPE")
	}
	if locale == "" {
		locale = os.Getenv("LANG")
	}
	locale = strings.ToUpper(locale)
	if locale != "" && !strings.Contains(locale, "UTF-8") && !strings.Contains(locale, "UTF8") {
		return Plain
	}
	return Unicode
}
