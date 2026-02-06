package unifiedpolicy

default allow = false

allow {
  count(input.evidence.vulnerabilities) < 10
  input.evidence.severity != "critical"
  contains(input.evidence.tags, "approved")
}

