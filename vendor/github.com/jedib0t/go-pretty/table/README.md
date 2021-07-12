# Table
[![GoDoc](https://godoc.org/github.com/jedib0t/go-pretty/table?status.svg)](https://godoc.org/github.com/jedib0t/go-pretty/table)

Pretty-print tables into ASCII/Unicode strings.

  - Add Rows one-by-one or as a group
  - Add Header(s) and Footer(s)
  - Auto Index Rows (1, 2, 3 ...) and Columns (A, B, C, ...)
  - Limit the length of the Rows; limit the length of individual Columns
  - Page results by a specified number of Lines
  - Alignment - Horizontal & Vertical
    - Auto (horizontal) Align (numeric columns are aligned Right)
    - Custom (horizontal) Align per column
    - Custom (vertical) VAlign per column (and multi-line column support)
  - Mirror output to an io.Writer object (like os.StdOut)
  - Sort by any of the Columns (by Column Name or Number)
  - Transformers to customize individual cell rendering
  - Completely customizable styles
    - Many ready-to-use styles: [style.go](style.go)
    - Colorize Headers/Body/Footers using [../text/color.go](../text/color.go)
    - Custom text-case for Headers/Body/Footers
    - Enable separators between each row
    - Render table without a Border
  - Render as:
    - (ASCII/Unicode) Table
    - CSV
    - HTML Table (with custom CSS Class)
    - Markdown Table


```
+---------------------------------------------------------------------+
| Game of Thrones                                                     +
+-----+------------+-----------+--------+-----------------------------+
|   # | FIRST NAME | LAST NAME | SALARY |                             |
+-----+------------+-----------+--------+-----------------------------+
|   1 | Arya       | Stark     |   3000 |                             |
|  20 | Jon        | Snow      |   2000 | You know nothing, Jon Snow! |
| 300 | Tyrion     | Lannister |   5000 |                             |
+-----+------------+-----------+--------+-----------------------------+
|     |            | TOTAL     |  10000 |                             |
+-----+------------+-----------+--------+-----------------------------+
```

A demonstration of all the capabilities can be found here:
[../cmd/demo-table](../cmd/demo-table)

If you want very specific examples, read ahead.

# Examples

All the examples below are going to start with the following block, although
nothing except a single Row is mandatory for the `Render()` function to render
something:
```go
package main

import (
    "os"

    "github.com/jedib0t/go-pretty/table"
)

func main() {
    t := table.NewWriter()
    t.SetOutputMirror(os.Stdout)
    t.AppendHeader(table.Row{"#", "First Name", "Last Name", "Salary"})
    t.AppendRows([]table.Row{
        {1, "Arya", "Stark", 3000},
        {20, "Jon", "Snow", 2000, "You know nothing, Jon Snow!"},
    })
    t.AppendRow([]interface{}{300, "Tyrion", "Lannister", 5000})
    t.AppendFooter(table.Row{"", "", "Total", 10000})
    t.Render()
}
```
Running the above will result in:
```
+-----+------------+-----------+--------+-----------------------------+
|   # | FIRST NAME | LAST NAME | SALARY |                             |
+-----+------------+-----------+--------+-----------------------------+
|   1 | Arya       | Stark     |   3000 |                             |
|  20 | Jon        | Snow      |   2000 | You know nothing, Jon Snow! |
| 300 | Tyrion     | Lannister |   5000 |                             |
+-----+------------+-----------+--------+-----------------------------+
|     |            | TOTAL     |  10000 |                             |
+-----+------------+-----------+--------+-----------------------------+
```

## Styles

You can customize almost every single thing about the table above. The previous
example just defaulted to `StyleDefault` during `Render()`. You can use a
ready-to-use style (as in [style.go](style.go)) or customize it as you want.

### Ready-to-use Styles

Table comes with a bunch of ready-to-use Styles that make the table look really
good. Set or Change the style using:
```go
    t.SetStyle(table.StyleLight)
    t.Render()
```
to get:
```
┌─────┬────────────┬───────────┬────────┬─────────────────────────────┐
│   # │ FIRST NAME │ LAST NAME │ SALARY │                             │
├─────┼────────────┼───────────┼────────┼─────────────────────────────┤
│   1 │ Arya       │ Stark     │   3000 │                             │
│  20 │ Jon        │ Snow      │   2000 │ You know nothing, Jon Snow! │
│ 300 │ Tyrion     │ Lannister │   5000 │                             │
├─────┼────────────┼───────────┼────────┼─────────────────────────────┤
│     │            │ TOTAL     │  10000 │                             │
└─────┴────────────┴───────────┴────────┴─────────────────────────────┘
```

Or if you want to use a full-color mode, and don't care for boxes, use:
```go
    t.SetStyle(table.StyleColoredBright)
    t.Render()
```
to get:

<img src="images/table-StyleColoredBright.png" width="640px"/>

### Roll your own Style

You can also roll your own style:
```go
    t.SetStyle(table.Style{
        Name: "myNewStyle",
        Box: table.BoxStyle{
            BottomLeft:       "\\",
            BottomRight:      "/",
            BottomSeparator:  "v",
            Left:             "[",
            LeftSeparator:    "{",
            MiddleHorizontal: "-",
            MiddleSeparator:  "+",
            MiddleVertical:   "|",
            PaddingLeft:      "<",
            PaddingRight:     ">",
            Right:            "]",
            RightSeparator:   "}",
            TopLeft:          "(",
            TopRight:         ")",
            TopSeparator:     "^",
            UnfinishedRow:    " ~~~",
        },
        Color: table.ColorOptions{
            AutoIndexColumn: nil,
            FirstColumn:     nil,
            Footer:          text.Colors{text.BgCyan, text.FgBlack},
            Header:          text.Colors{text.BgHiCyan, text.FgBlack},
            Row:             text.Colors{text.BgHiWhite, text.FgBlack},
            RowAlternate:    text.Colors{text.BgWhite, text.FgBlack},
        },
        Format: table.FormatOptions{
            Footer: text.FormatUpper,
            Header: text.FormatUpper,
            Row:    text.FormatDefault,
        },
        Options: table.Options{
            DrawBorder:      true,
            SeparateColumns: true,
            SeparateFooter:  true,
            SeparateHeader:  true,
            SeparateRows:    false,
        },
    })
```

Or you can use one of the ready-to-use Styles, and just make a few tweaks:
```go
    t.SetStyle(table.StyleLight)
    t.Style().Color.Header = text.Colors{text.BgHiCyan, text.FgBlack}
    t.Style().Format.Footer = text.FormatLower
    t.Style().Options.DrawBorder = false
```

## Paging

You can limit then number of lines rendered in a single "Page". This logic
can handle rows with multiple lines too. Here is a simple example:
```go
    t.SetPageSize(1)
    t.Render()
```
to get:
```
+-----+------------+-----------+--------+-----------------------------+
|   # | FIRST NAME | LAST NAME | SALARY |                             |
+-----+------------+-----------+--------+-----------------------------+
|   1 | Arya       | Stark     |   3000 |                             |
+-----+------------+-----------+--------+-----------------------------+
|     |            | TOTAL     |  10000 |                             |
+-----+------------+-----------+--------+-----------------------------+

+-----+------------+-----------+--------+-----------------------------+
|   # | FIRST NAME | LAST NAME | SALARY |                             |
+-----+------------+-----------+--------+-----------------------------+
|  20 | Jon        | Snow      |   2000 | You know nothing, Jon Snow! |
+-----+------------+-----------+--------+-----------------------------+
|     |            | TOTAL     |  10000 |                             |
+-----+------------+-----------+--------+-----------------------------+

+-----+------------+-----------+--------+-----------------------------+
|   # | FIRST NAME | LAST NAME | SALARY |                             |
+-----+------------+-----------+--------+-----------------------------+
| 300 | Tyrion     | Lannister |   5000 |                             |
+-----+------------+-----------+--------+-----------------------------+
|     |            | TOTAL     |  10000 |                             |
+-----+------------+-----------+--------+-----------------------------+
```

## Wrapping (or) Row/Column Width restrictions

You can restrict the maximum (text) width for a Row:
```go
    t.SetAllowedRowLength(50)
    t.Render()
```
to get:
```
+-----+------------+-----------+--------+------- ~
|   # | FIRST NAME | LAST NAME | SALARY |        ~
+-----+------------+-----------+--------+------- ~
|   1 | Arya       | Stark     |   3000 |        ~
|  20 | Jon        | Snow      |   2000 | You kn ~
| 300 | Tyrion     | Lannister |   5000 |        ~
+-----+------------+-----------+--------+------- ~
|     |            | TOTAL     |  10000 |        ~
+-----+------------+-----------+--------+------- ~
```

## Column Control - Alignment, Colors, Width and more

You can control a lot of things about individual cells/columns which overrides
global properties/styles using the `SetColumnConfig()` interface:
- Alignment (horizontal & vertical)
- Colorization
- Transform individual cells based on the content
- Width (minimum & maximum)

```go
    nameTransformer := text.Transformer(func(val interface{}) string {
    	return text.Bold.Sprint(val)
    })

    t.SetColumnConfigs([]ColumnConfig{
        {
            Name:              "First Name",
            Align:             text.AlignLeft,
            AlignFooter:       text.AlignLeft,
            AlignHeader:       text.AlignLeft,
            Colors:            text.Colors{text.BgBlack, text.FgRed},
            ColorsHeader:      text.Colors{text.BgRed, text.FgBlack, text.Bold},
            ColorsFooter:      text.Colors{text.BgRed, text.FgBlack},
            Transformer:       nameTransformer,
            TransformerFooter: nameTransformer,
            TransformerHeader: nameTransformer,
            VAlign:            text.VAlignMiddle,
            VAlignFooter:      text.VAlignTop,
            VAlignHeader:      text.VAlignBottom,
            WidthMin:          6,
            WidthMax:          64,
        }
    })
```

## Render As ...

Tables can be rendered in other common formats such as:

### ... CSV

```go
    t.RenderCSV()
```
to get:
```
,First Name,Last Name,Salary,
1,Arya,Stark,3000,
20,Jon,Snow,2000,"You know nothing\, Jon Snow!"
300,Tyrion,Lannister,5000,
,,Total,10000,
```

### ... HTML Table

```go
    t.RenderHTML()
```
to get:
```html
<table class="go-pretty-table">
  <thead>
  <tr>
    <th align="right">#</th>
    <th>First Name</th>
    <th>Last Name</th>
    <th align="right">Salary</th>
    <th>&nbsp;</th>
  </tr>
  </thead>
  <tbody>
  <tr>
    <td align="right">1</td>
    <td>Arya</td>
    <td>Stark</td>
    <td align="right">3000</td>
    <td>&nbsp;</td>
  </tr>
  <tr>
    <td align="right">20</td>
    <td>Jon</td>
    <td>Snow</td>
    <td align="right">2000</td>
    <td>You know nothing, Jon Snow!</td>
  </tr>
  <tr>
    <td align="right">300</td>
    <td>Tyrion</td>
    <td>Lannister</td>
    <td align="right">5000</td>
    <td>&nbsp;</td>
  </tr>
  </tbody>
  <tfoot>
  <tr>
    <td align="right">&nbsp;</td>
    <td>&nbsp;</td>
    <td>Total</td>
    <td align="right">10000</td>
    <td>&nbsp;</td>
  </tr>
  </tfoot>
</table>
```

### ... Markdown Table

```go
    t.RenderMarkdown()
```
to get:
```markdown
| # | First Name | Last Name | Salary |  |
| ---:| --- | --- | ---:| --- |
| 1 | Arya | Stark | 3000 |  |
| 20 | Jon | Snow | 2000 | You know nothing, Jon Snow! |
| 300 | Tyrion | Lannister | 5000 |  |
|  |  | Total | 10000 |  |
```
