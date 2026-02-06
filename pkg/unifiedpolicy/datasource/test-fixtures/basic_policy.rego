package unifiedpolicy

default allow = false

allow {
  input.evidence.severity != "critical"
}

