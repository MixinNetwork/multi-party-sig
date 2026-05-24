package test

func SessionID(name string) []byte {
	return []byte("test-session-id:" + name)
}
