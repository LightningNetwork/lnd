package table

import (
	"html"
	"strings"
)

const (
	// DefaultHTMLCSSClass stores the css-class to use when none-provided via
	// SetHTMLCSSClass(cssClass string).
	DefaultHTMLCSSClass = "go-pretty-table"
)

// RenderHTML renders the Table in HTML format. Example:
//  <table class="go-pretty-table">
//    <thead>
//    <tr>
//      <th align="right">#</th>
//      <th>First Name</th>
//      <th>Last Name</th>
//      <th align="right">Salary</th>
//      <th>&nbsp;</th>
//    </tr>
//    </thead>
//    <tbody>
//    <tr>
//      <td align="right">1</td>
//      <td>Arya</td>
//      <td>Stark</td>
//      <td align="right">3000</td>
//      <td>&nbsp;</td>
//    </tr>
//    <tr>
//      <td align="right">20</td>
//      <td>Jon</td>
//      <td>Snow</td>
//      <td align="right">2000</td>
//      <td>You know nothing, Jon Snow!</td>
//    </tr>
//    <tr>
//      <td align="right">300</td>
//      <td>Tyrion</td>
//      <td>Lannister</td>
//      <td align="right">5000</td>
//      <td>&nbsp;</td>
//    </tr>
//    </tbody>
//    <tfoot>
//    <tr>
//      <td align="right">&nbsp;</td>
//      <td>&nbsp;</td>
//      <td>Total</td>
//      <td align="right">10000</td>
//      <td>&nbsp;</td>
//    </tr>
//    </tfoot>
//  </table>
func (t *Table) RenderHTML() string {
	t.initForRender()

	var out strings.Builder
	if t.numColumns > 0 {
		out.WriteString("<table class=\"")
		if t.htmlCSSClass != "" {
			out.WriteString(t.htmlCSSClass)
		} else {
			out.WriteString(DefaultHTMLCSSClass)
		}
		out.WriteString("\">\n")
		t.htmlRenderRows(&out, t.rowsHeader, renderHint{isHeaderRow: true})
		t.htmlRenderRows(&out, t.rows, renderHint{})
		t.htmlRenderRows(&out, t.rowsFooter, renderHint{isFooterRow: true})
		out.WriteString("</table>")
	}
	return t.render(&out)
}

func (t *Table) htmlRenderRow(out *strings.Builder, row rowStr, hint renderHint) {
	out.WriteString("  <tr>\n")
	for colIdx := 0; colIdx < t.numColumns; colIdx++ {
		var colStr string
		if colIdx < len(row) {
			colStr = row[colIdx]
		}

		// header uses "th" instead of "td"
		colTagName := "td"
		if hint.isHeaderRow {
			colTagName = "th"
		}

		// determine the HTML "align"/"valign" property values
		align := t.getAlign(colIdx, hint).HTMLProperty()
		vAlign := t.getVAlign(colIdx, hint).HTMLProperty()
		// determine the HTML "class" property values for the colors
		class := t.getColumnColors(colIdx, hint).HTMLProperty()

		// write the row
		out.WriteString("    <")
		out.WriteString(colTagName)
		if align != "" {
			out.WriteRune(' ')
			out.WriteString(align)
		}
		if class != "" {
			out.WriteRune(' ')
			out.WriteString(class)
		}
		if vAlign != "" {
			out.WriteRune(' ')
			out.WriteString(vAlign)
		}
		out.WriteString(">")
		if len(colStr) > 0 {
			out.WriteString(strings.Replace(html.EscapeString(colStr), "\n", "<br/>", -1))
		} else {
			out.WriteString("&nbsp;")
		}
		out.WriteString("</")
		out.WriteString(colTagName)
		out.WriteString(">\n")
	}
	out.WriteString("  </tr>\n")
}

func (t *Table) htmlRenderRows(out *strings.Builder, rows []rowStr, hint renderHint) {
	if len(rows) > 0 {
		// determine that tag to use based on the type of the row
		rowsTag := "tbody"
		if hint.isHeaderRow {
			rowsTag = "thead"
		} else if hint.isFooterRow {
			rowsTag = "tfoot"
		}

		var renderedTagOpen, shouldRenderTagClose bool
		for idx, row := range rows {
			hint.rowNumber = idx + 1
			if len(row) > 0 {
				if !renderedTagOpen {
					out.WriteString("  <")
					out.WriteString(rowsTag)
					out.WriteString(">\n")
					renderedTagOpen = true
				}
				t.htmlRenderRow(out, row, hint)
				shouldRenderTagClose = true
			}
		}
		if shouldRenderTagClose {
			out.WriteString("  </")
			out.WriteString(rowsTag)
			out.WriteString(">\n")
		}
	}
}
