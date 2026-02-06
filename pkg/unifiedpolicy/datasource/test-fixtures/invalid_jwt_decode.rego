package unifiedpolicy

default allow = false

allow {
    io.jwt.decode(input.token)
}

