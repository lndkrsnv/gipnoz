package crypto

import "testing"

func TestGeneratePaddingBounds(t *testing.T) {
	for i := 0; i < 1000; i++ {
		p, err := GeneratePadding(16, 256)
		if err != nil {
			t.Fatalf("GeneratePadding: %v", err)
		}
		if len(p) < 16 || len(p) > 256 {
			t.Fatalf("padding length %d out of [16, 256]", len(p))
		}
	}
}

func TestGeneratePaddingFixedSize(t *testing.T) {
	p, err := GeneratePadding(64, 64)
	if err != nil {
		t.Fatalf("GeneratePadding: %v", err)
	}
	if len(p) != 64 {
		t.Fatalf("want 64 bytes, got %d", len(p))
	}
}

func TestGeneratePaddingInvalidRange(t *testing.T) {
	if _, err := GeneratePadding(-1, 10); err == nil {
		t.Fatal("expected error for negative min")
	}
	if _, err := GeneratePadding(100, 10); err == nil {
		t.Fatal("expected error for min > max")
	}
}
