package adminstore

const (
	// DefaultPageSize is the page size used when no page_size is provided.
	DefaultPageSize = 50
	// MaxPageSize is the upper bound for page_size.
	MaxPageSize = 100
)

// PageFilter carries LIMIT/OFFSET pagination parameters for List* store methods.
// Page is 1-based: page=1 returns the first PageSize rows. Zero/negative values
// are normalised by NewPageFilter.
type PageFilter struct {
	Page     int
	PageSize int
	// Sort, when non-nil and Set, selects an allowlisted sort column and
	// direction (see OrderBy). Nil/Unset keeps the endpoint's default order.
	Sort *Sort
}

// NewPageFilter constructs a PageFilter with sensible defaults and clamps.
//   - page < 1 → 1
//   - pageSize < 1 → DefaultPageSize
//   - pageSize > MaxPageSize → MaxPageSize
func NewPageFilter(page, pageSize int) PageFilter {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = DefaultPageSize
	}
	if pageSize > MaxPageSize {
		pageSize = MaxPageSize
	}
	return PageFilter{Page: page, PageSize: pageSize}
}

// Offset returns the SQL OFFSET value for this page (0-based).
func (f PageFilter) Offset() int { return (f.Page - 1) * f.PageSize }

// TotalPages returns the total number of pages for a given total row count.
func (f PageFilter) TotalPages(total int64) int {
	if f.PageSize <= 0 {
		return 0
	}
	pages := int(total) / f.PageSize
	if int(total)%f.PageSize != 0 {
		pages++
	}
	return pages
}
