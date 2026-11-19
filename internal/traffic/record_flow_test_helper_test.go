package traffic

// recordFlow is a test helper that records a synthetic exchange, mirroring what the
// Burp ingest does.
func (t *Traffic) recordFlow(ex exchange) { t.record(ex) }
