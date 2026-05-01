package risk

import "testing"

func TestParse(t *testing.T) {
	cases := []struct {
		input string
		want  Level
	}{
		{"none", None},
		{"low", Low},
		{"medium", Medium},
		{"high", High},
		{"unknown", None},
		{"", None},
	}
	for _, c := range cases {
		got := Parse(c.input)
		if got != c.want {
			t.Errorf("Parse(%q) = %v, want %v", c.input, got, c.want)
		}
	}
}

func TestValid(t *testing.T) {
	valid := []string{"none", "low", "medium", "high"}
	for _, s := range valid {
		if !Valid(s) {
			t.Errorf("Valid(%q) should be true", s)
		}
	}
	invalid := []string{"", "critical", "info", "LOW"}
	for _, s := range invalid {
		if Valid(s) {
			t.Errorf("Valid(%q) should be false", s)
		}
	}
}

func TestGTE(t *testing.T) {
	if !GTE(High, Medium) {
		t.Error("High should be >= Medium")
	}
	if !GTE(Medium, Medium) {
		t.Error("Medium should be >= Medium")
	}
	if GTE(Low, Medium) {
		t.Error("Low should not be >= Medium")
	}
	if GTE(None, Low) {
		t.Error("None should not be >= Low")
	}
}
