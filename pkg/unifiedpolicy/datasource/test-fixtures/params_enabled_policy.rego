package unifiedpolicy

default allow = false

allow {
  input.evidence.enabled == input.params.enabled
}

