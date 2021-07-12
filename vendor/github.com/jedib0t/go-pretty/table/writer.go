package table

import (
	"io"

	"github.com/jedib0t/go-pretty/text"
)

// Writer declares the interfaces that can be used to setup and render a table.
type Writer interface {
	AppendFooter(row Row)
	AppendHeader(row Row)
	AppendRow(row Row)
	AppendRows(rows []Row)
	Length() int
	Render() string
	RenderCSV() string
	RenderHTML() string
	RenderMarkdown() string
	SetAllowedRowLength(length int)
	SetAutoIndex(autoIndex bool)
	SetCaption(format string, a ...interface{})
	SetColumnConfigs(configs []ColumnConfig)
	SetHTMLCSSClass(cssClass string)
	SetIndexColumn(colNum int)
	SetOutputMirror(mirror io.Writer)
	SetPageSize(numLines int)
	SetRowPainter(painter RowPainter)
	SetStyle(style Style)
	SetTitle(format string, a ...interface{})
	SortBy(sortBy []SortBy)
	Style() *Style

	// deprecated; use SetColumnConfigs instead
	SetAlign(align []text.Align)
	// deprecated; use SetColumnConfigs instead
	SetAlignFooter(align []text.Align)
	// deprecated; use SetColumnConfigs instead
	SetAlignHeader(align []text.Align)
	// deprecated; use SetColumnConfigs instead
	SetAllowedColumnLengths(lengths []int)
	// deprecated; use SetColumnConfigs instead
	SetColors(colors []text.Colors)
	// deprecated; use SetColumnConfigs instead
	SetColorsFooter(colors []text.Colors)
	// deprecated; use SetColumnConfigs instead
	SetColorsHeader(colors []text.Colors)
	// deprecated; use SetColumnConfigs instead
	SetVAlign(vAlign []text.VAlign)
	// deprecated; use SetColumnConfigs instead
	SetVAlignFooter(vAlign []text.VAlign)
	// deprecated; use SetColumnConfigs instead
	SetVAlignHeader(vAlign []text.VAlign)
}

// NewWriter initializes and returns a Writer.
func NewWriter() Writer {
	return &Table{}
}
