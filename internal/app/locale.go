package app

import (
	"embed"
	"encoding/json"
	"fmt"
)

//go:embed locales/*.json
var localeFiles embed.FS

type messages map[string]string

var activeMessages messages

func loadLocale(name string) (messages, error) {
	b, err := localeFiles.ReadFile("locales/" + name + ".json")
	if err != nil {
		return nil, fmt.Errorf("unsupported locale %q", name)
	}
	var m messages
	return m, json.Unmarshal(b, &m)
}

func localizedError(code, fallback string) string {
	if activeMessages != nil {
		if message := activeMessages["error."+code]; message != "" {
			return message
		}
	}
	return fallback
}

func chooseLanguage() string {
	names := []string{"en", "zh_CN"}
	for i, name := range names {
		m, _ := loadLocale(name)
		fmt.Printf("%d) %s\n", i+1, m["language_name"])
	}
	fmt.Print("> ")
	var selection string
	fmt.Scanln(&selection)
	if selection == "2" {
		return "zh_CN"
	}
	return "en"
}
