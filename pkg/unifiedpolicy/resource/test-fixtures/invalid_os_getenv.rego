package unifiedpolicy

default allow = false

allow {
    os.getenv("PATH")
}

