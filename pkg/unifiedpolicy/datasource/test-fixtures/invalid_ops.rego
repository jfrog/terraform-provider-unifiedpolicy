package unifiedpolicy

default allow = false

allow {
    # Invalid: http.send is NOT in the allowed operations list
    http.send({"method": "GET", "url": "https://example.com"})
    # Invalid: io.jwt.decode is NOT in the allowed operations list
    io.jwt.decode(input.token)
    # Invalid: rand.intn is NOT in the allowed operations list
    rand.intn(100)
    # This is valid (comparison operator)
    input.evidence.severity != "critical"
}

