package adminstore

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewPageFilter_DefaultsWhenZero(t *testing.T) {
	f := NewPageFilter(0, 0)
	assert.Equal(t, 1, f.Page)
	assert.Equal(t, DefaultPageSize, f.PageSize)
}

func TestNewPageFilter_ClampsNegative(t *testing.T) {
	f := NewPageFilter(-5, -10)
	assert.Equal(t, 1, f.Page)
	assert.Equal(t, DefaultPageSize, f.PageSize)
}

func TestNewPageFilter_ClampsPageSizeToMax(t *testing.T) {
	f := NewPageFilter(1, 1000)
	assert.Equal(t, MaxPageSize, f.PageSize)
}

func TestNewPageFilter_PreservesValidValues(t *testing.T) {
	f := NewPageFilter(3, 25)
	assert.Equal(t, 3, f.Page)
	assert.Equal(t, 25, f.PageSize)
}

func TestPageFilter_Offset(t *testing.T) {
	cases := []struct {
		page, size, want int
	}{
		{1, 50, 0},
		{2, 50, 50},
		{3, 25, 50},
		{10, 100, 900},
	}
	for _, c := range cases {
		f := NewPageFilter(c.page, c.size)
		assert.Equal(t, c.want, f.Offset(), "page=%d size=%d", c.page, c.size)
	}
}

func TestPageFilter_TotalPages(t *testing.T) {
	f := NewPageFilter(1, 50)
	assert.Equal(t, 0, f.TotalPages(0))
	assert.Equal(t, 1, f.TotalPages(1))
	assert.Equal(t, 1, f.TotalPages(50))
	assert.Equal(t, 2, f.TotalPages(51))
	assert.Equal(t, 2, f.TotalPages(100))
	assert.Equal(t, 3, f.TotalPages(101))
}
