package validation

import "testing"

func TestCanonicalDNSName(t *testing.T) {
	got, err := CanonicalDNSName("Example.Example.Com.")
	if err != nil {
		t.Fatal(err)
	}
	if got != "example.example.com" {
		t.Fatalf("got %q", got)
	}
	for _, value := range []string{"", "localhost", "printer", "*.example.com", "bad_label.example.com", "-bad.example.com"} {
		if _, err := CanonicalDNSName(value); err == nil {
			t.Fatalf("expected %q to be rejected", value)
		}
	}
}

func TestRoomIDContract(t *testing.T) {
	roomID := "security/risk brainstorm #1"
	got, err := NormalizeRoomID(roomID)
	if err != nil {
		t.Fatal(err)
	}
	if got != roomID {
		t.Fatalf("got %q", got)
	}
	key, err := RoomKey(roomID)
	if err != nil {
		t.Fatal(err)
	}
	if key == "" || key == roomID {
		t.Fatalf("expected encoded room key, got %q", key)
	}
	for _, value := range []string{"", " leading", "trailing ", "bad\nroom"} {
		if _, err := NormalizeRoomID(value); err == nil {
			t.Fatalf("expected %q to be rejected", value)
		}
	}
}

func TestNicknameContract(t *testing.T) {
	display, key, err := Nickname("Wolfgang_01")
	if err != nil {
		t.Fatal(err)
	}
	if display != "Wolfgang_01" || key != "wolfgang_01" {
		t.Fatalf("nickname = %q key=%q", display, key)
	}
	for _, value := range []string{
		"",
		" leading",
		"trailing ",
		"-dash",
		"dot.",
		"has space",
		"unicode-é",
		"wolfgang!",
		"abcdefghijklmnopqrstuvwxyzabcdefg",
	} {
		if _, _, err := Nickname(value); err == nil {
			t.Fatalf("expected %q to be rejected", value)
		}
	}
}
