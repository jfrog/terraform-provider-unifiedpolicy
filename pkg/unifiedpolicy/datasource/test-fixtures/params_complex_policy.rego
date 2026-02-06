package unifiedpolicy

default allow = false

allow {
  input.evidence.severity == input.params.severity
  input.evidence.count < input.params.max_count
  input.evidence.enabled == input.params.enabled
}

