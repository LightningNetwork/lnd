package table

import (
	"strings"
	"unicode/utf8"
)

// RenderCSV renders the Table in CSV format. Example:
//  #,First Name,Last Name,Salary,
//  1,Arya,Stark,3000,
//  20,Jon,Snow,2000,"You know nothing\, Jon Snow!"
//  300,Tyrion,Lannister,5000,
//  ,,Total,10000,
func (t *Table) RenderCSV() string {
	t.initForRender()

	var out strings.Builder
	if t.numColumns > 0 {
		if t.title != "" {
			out.WriteString(t.title)
		}
		t.csvRenderRows(&out, t.rowsHeader)
		t.csvRenderRows(&out, t.rows)
		t.csvRenderRows(&out, t.rowsFooter)
		if t.caption != "" {
			out.WriteRune('\n')
			out.WriteString(t.caption)
		}
	}
	return t.render(&out)
}

func (t *Table) csvFixCommas(str string) string {
	return strings.Replace(str, ",", "\\,", -1)
}

func (t *Table) csvFixDoubleQuotes(str string) string {
	return strings.Replace(str, "\"", "\\\"", -1)
}

func (t *Table) csvRenderRow(out *strings.Builder, row rowStr) {
	// when working on line number 2 or more, insert a newline first
	if out.Len() > 0 {
		out.WriteRune('\n')
	}

	// generate the columns to render in CSV format and append to "out"
	for colIdx, colStr := range row {
		if colIdx > 0 {
			out.WriteRune(',')
		}
		if strings.ContainsAny(colStr, "\",\n") {
			out.WriteRune('"')
			out.WriteString(t.csvFixCommas(t.csvFixDoubleQuotes(colStr)))
			out.WriteRune('"')
		} else if utf8.RuneCountInString(colStr) > 0 {
			out.WriteString(colStr)
		}
	}
	for colIdx := len(row); colIdx < t.numColumns; colIdx++ {
		out.WriteRune(',')
	}
}

func (t *Table) csvRenderRows(out *strings.Builder, rows []rowStr) {
	for _, row := range rows {
		t.csvRenderRow(out, row)
	}
}
