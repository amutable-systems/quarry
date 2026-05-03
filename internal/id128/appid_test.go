// Copyright (C) 2026 Amutable GmbH

package id128

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestToUUIDv4(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   [16]byte
		want uuid.UUID
	}{
		{
			name: "AllZero",
			in:   [16]byte{},
			want: uuid.MustParse("00000000-0000-4000-8000-000000000000"),
		},
		{
			name: "AllOnes",
			in: [16]byte{
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			},
			want: uuid.MustParse("ffffffff-ffff-4fff-bfff-ffffffffffff"),
		},
		{
			// Catches a 0x04-instead-of-0x0F regression in the byte 6 mask.
			name: "Byte6_PreservesLowBit3",
			in:   [16]byte{0, 0, 0, 0, 0, 0, 0x88, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			want: uuid.MustParse("00000000-0000-4800-8000-000000000000"),
		},
		{
			name: "Byte6_PreservesLowBits01",
			in:   [16]byte{0, 0, 0, 0, 0, 0, 0xa3, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			want: uuid.MustParse("00000000-0000-4300-8000-000000000000"),
		},
		{
			name: "Byte8_Variant00",
			in:   [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0x12, 0, 0, 0, 0, 0, 0, 0},
			want: uuid.MustParse("00000000-0000-4000-9200-000000000000"),
		},
		{
			name: "Byte8_Variant01",
			in:   [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0x55, 0, 0, 0, 0, 0, 0, 0},
			want: uuid.MustParse("00000000-0000-4000-9500-000000000000"),
		},
		{
			name: "Byte8_Variant10",
			in:   [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0xab, 0, 0, 0, 0, 0, 0, 0},
			want: uuid.MustParse("00000000-0000-4000-ab00-000000000000"),
		},
		{
			name: "Byte8_Variant11",
			in:   [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0xc3, 0, 0, 0, 0, 0, 0, 0},
			want: uuid.MustParse("00000000-0000-4000-8300-000000000000"),
		},
		{
			name: "OtherBytesUntouched",
			in: [16]byte{
				0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x00, 0xba,
				0x00, 0xbe, 0xfe, 0xed, 0xfa, 0xce, 0xf0, 0x0d,
			},
			want: uuid.MustParse("deadbeef-cafe-40ba-80be-feedfacef00d"),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, toUUIDv4(tc.in))
		})
	}
}

// Vectors generated via `systemd-id128 show <base> --app-specific=<app>`.
func TestAppSpecificID(t *testing.T) {
	for _, tc := range []struct {
		name string
		base string
		app  string
		want string
	}{
		{
			name: "FixedBaseFixedApp",
			base: "618feedb-a0d9-4c71-a3da-b7573d4433ce",
			app:  "ce8f5f01-e9f3-4a2f-8b16-ec8d6e5c9b41",
			want: "7676b182-7c93-408a-8a1b-05eff831149a",
		},
		{
			// HMAC produces 0x88 at byte 6: integration canary for the
			// 0x04-vs-0x0F mask regression.
			name: "HmacByte6Bit3Set",
			base: "618feedb-a0d9-4c71-a3da-b7573d4433ce",
			app:  "00000000-0000-0000-0000-0222b185413c",
			want: "dfbfdf42-01ef-4832-9c92-7b89cd1d3b2d",
		},
		{
			name: "ZeroBase",
			base: "00000000-0000-0000-0000-000000000000",
			app:  "deadbeef-dead-beef-dead-beefdeadbeef",
			want: "732f7beb-8fd1-41bf-ae19-736a38234a06",
		},
		{
			name: "AllOnesBase",
			base: "ffffffff-ffff-ffff-ffff-ffffffffffff",
			app:  "01234567-89ab-cdef-0123-456789abcdef",
			want: "42ab4aec-d842-4028-bfb6-8dba566698a5",
		},
		{
			name: "DiverseInputs1",
			base: "deadbeef-cafe-babe-feed-facecafef00d",
			app:  "11111111-1111-1111-1111-11111111aaaa",
			want: "7b2c0462-7027-49f9-80bb-01a267d4b468",
		},
		{
			name: "DiverseInputs2",
			base: "deadbeef-cafe-babe-feed-facecafef00d",
			app:  "00000000-0000-0000-0000-00000000ffff",
			want: "20f9e7e7-8e1f-4879-aea3-a1498480406c",
		},
		{
			name: "DiverseInputs3",
			base: "11111111-2222-2222-3333-333344444444",
			app:  "55555555-6666-6666-7777-77778888aaaa",
			want: "8ce3bbc2-1787-47b1-ba31-67eed08daead",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := appSpecificID(uuid.MustParse(tc.base), uuid.MustParse(tc.app))
			assert.Equal(t, uuid.MustParse(tc.want), got)
		})
	}
}

func TestAppSpecificID_KeyMessageOrdering(t *testing.T) {
	a := uuid.MustParse("618feedb-a0d9-4c71-a3da-b7573d4433ce")
	b := uuid.MustParse("ce8f5f01-e9f3-4a2f-8b16-ec8d6e5c9b41")
	require.NotEqual(t, appSpecificID(a, b), appSpecificID(b, a))
}

func TestAppSpecificID_Deterministic(t *testing.T) {
	base := uuid.MustParse("618feedb-a0d9-4c71-a3da-b7573d4433ce")
	app := uuid.MustParse("ce8f5f01-e9f3-4a2f-8b16-ec8d6e5c9b41")
	first := appSpecificID(base, app)
	for range 5 {
		assert.Equal(t, first, appSpecificID(base, app))
	}
}

// Expected value is computed at runtime to avoid embedding any hash that
// depends on the host's machine-id.
func TestMachineAppSpecificID(t *testing.T) {
	machineID, err := MachineID()
	if err != nil {
		t.Skipf("MachineID unavailable on this host: %v", err)
	}

	app := uuid.MustParse("ce8f5f01-e9f3-4a2f-8b16-ec8d6e5c9b41")
	want := appSpecificID(machineID, app)

	got, err := MachineAppSpecificID(app)
	require.NoError(t, err)
	assert.Equal(t, want, got)
}
