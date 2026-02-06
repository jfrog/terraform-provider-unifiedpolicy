package unifiedpolicy

default allow = false

allow {
    http.send({"method": "GET", "url": "https://example.com"})
}

