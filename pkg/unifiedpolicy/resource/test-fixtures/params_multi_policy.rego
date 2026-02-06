package unifiedpolicy

default allow = false

allow {
  input.evidence.severity != input.params.severity_threshold
  input.evidence.count < input.params.max_count
}

