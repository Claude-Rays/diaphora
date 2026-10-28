"""
Diaphora, a diffing plugin for Ghidra: user interface
Copyright (c) 2015-2026 Joxean Koret
Copyright (c) 2026 ClaudeMonkey (PyGhidra port)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

import re
import sys
import difflib
import traceback

# pylint: disable=import-error
from jpype import JImplements, JOverride
from java.awt import Color, Dimension
from java.lang import Integer as JInteger, String as JString
from javax.swing import JEditorPane, JFrame, JScrollPane, SwingUtilities, WindowConstants
from docking.action.builder import ActionBuilder
from docking.widgets.table import GTableCellRenderer, GTableCellRenderingData, TableSortState
from ghidra.docking.settings import SettingsImpl
from ghidra.app.plugin.core.colorizer import ColorizingService
from ghidra.util import Msg
# pylint: enable=import-error

from pygments import highlight
from pygments.lexers import NasmLexer, CppLexer, DiffLexer
from pygments.formatters import HtmlFormatter

import diaphora_config as config

import diaphora
import diaphora_ghidra
from diaphora_ghidra import log

#-------------------------------------------------------------------------------
# Indices of the items of diaphora.CChooser.items
COL_LINE = 0
COL_EA1 = 1
COL_NAME1 = 2
COL_EA2 = 3
COL_NAME2 = 4
COL_RATIO = 5
COL_NODES1 = 6
COL_NODES2 = 7
COL_DESC = 8

MATCH_COLUMNS = [
  ("Name", COL_NAME1, str),
  ("Address 2", COL_EA2, str),
  ("Name 2", COL_NAME2, str),
  ("Ratio", COL_RATIO, float),
  ("BBlocks 1", COL_NODES1, int),
  ("BBlocks 2", COL_NODES2, int),
  ("Description", COL_DESC, str),
]

UNMATCHED_COLUMNS = [
  ("Name", COL_NAME1, str),
]

OWNER = "Diaphora"

# Colour of the rows that seem false positives (IDA's bgcolor_t, 0xBBGGRR)
LITTLE_ORANGE = 0x026AFD

# The row and highlight colours are designed for IDA's white background, so they
# are mixed with the background to keep the text readable with any theme.
ROW_COLOR_STRENGTH = 0.55
DARK_HIGHLIGHT_STRENGTH = 0.40
DARK_BASE = Color(0x20, 0x20, 0x20)

# Keep a reference to the opened windows and choosers to avoid them being
# garbage collected while they are still visible.
g_windows = []

#-------------------------------------------------------------------------------
def is_dark_mode():
  try:
    # pylint: disable=import-error
    from generic.theme import Gui
    # pylint: enable=import-error
    return Gui.isDarkTheme()
  except:
    return False

#-------------------------------------------------------------------------------
def get_style():
  if is_dark_mode():
    return "native"
  return "default"

#-------------------------------------------------------------------------------
def warning(message):
  Msg.showWarn(OWNER, None, OWNER, message)

#-------------------------------------------------------------------------------
def bgr_to_color(bgr):
  """ Convert an IDA's bgcolor_t value (0xBBGGRR) to a Java colour
  """
  return Color(bgr & 0xFF, (bgr >> 8) & 0xFF, (bgr >> 16) & 0xFF)

#-------------------------------------------------------------------------------
def mix_colors(color, base, strength):
  """ Mix @color over @base: strength 1.0 is @color and 0.0 is @base
  """
  def mix(a, b):
    return max(0, min(255, round(b + (a - b) * strength)))

  return Color(
    mix(color.getRed(), base.getRed()),
    mix(color.getGreen(), base.getGreen()),
    mix(color.getBlue(), base.getBlue()),
  )

#-------------------------------------------------------------------------------
def seems_false_positive(item):
  """
  Check if it looks like a false positive because the names are different (the
  same check done by the IDA's choosers).
  """
  name1 = item[COL_NAME1].rstrip("_0").strip(".")
  name2 = item[COL_NAME2].rstrip("_0").strip(".")

  if not name1.startswith("sub_") and not name2.startswith("sub_"):
    if name1 != name2:
      if name2.find(name1) == -1 and name1.find(name2) != -1:
        return True

  return False

#-------------------------------------------------------------------------------
def get_row_color(item, background):
  """
  Return the colour of a match row, as OnGetLineAttr() does in diaphora_ida.py:
  from green (ratio 1.0) to purple (ratio 0.0), or orange for matches that seem
  false positives.
  """
  if seems_false_positive(item):
    color = bgr_to_color(LITTLE_ORANGE)
  else:
    ratio = max(0.0, min(1.0, float(item[COL_RATIO])))
    red = abs(int(164 * (1 - ratio)))
    green = abs(int(128 * ratio))
    blue = abs(int(255 * (1 - ratio)))
    color = Color(red, green, blue)

  if background is None:
    background = DARK_BASE if is_dark_mode() else Color.WHITE
  return mix_colors(color, background, ROW_COLOR_STRENGTH)

#-------------------------------------------------------------------------------
def get_highlight_color(bgr):
  color = bgr_to_color(bgr)
  if is_dark_mode():
    color = mix_colors(color, DARK_BASE, DARK_HIGHLIGHT_STRENGTH)
  return color

#-------------------------------------------------------------------------------
class CHtmlViewer:
  """
  A simple Swing window to show HTML content (diffs, assembly, pseudo-code...).
  """

  def show(self, html, title):
    def do_show():
      pane = JEditorPane("text/html", html)
      pane.setEditable(False)
      pane.setCaretPosition(0)

      frame = JFrame(title)
      frame.setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE)
      frame.getContentPane().add(JScrollPane(pane))
      frame.setPreferredSize(Dimension(1200, 800))
      frame.pack()
      frame.setLocationByPlatform(True)
      frame.setVisible(True)

    if SwingUtilities.isEventDispatchThread():
      do_show()
    else:
      SwingUtilities.invokeLater(do_show)

#-------------------------------------------------------------------------------
class CHtmlDiff:
  """A replacement for difflib.HtmlDiff that tries to enforce a max width

  The main challenge is to do this given the limitations of Swing's HTML
  renderer, that only implements a minimum of CSS.
  """

  _html_template = """
  <html>
  <head>
  <style>%(style)s</style>
  </head>
  <body>
  <table class="diff_tab" cellspacing=0>
  %(rows)s
  </table>
  </body>
  </html>
  """

  @property
  def _style(self):
    if is_dark_mode():
      lineno_bg = "#333333"
    else:
      lineno_bg = config.DIFF_COLOR_LINE_NO
    return (
      """
  table.diff_tab {
  font-family: Courier, monospace;
  width: 100%;
  }

  .diff_add {
  background-color: """
      + config.DIFF_COLOR_ADDED
      + """;
  color: #000000;
  }
  .diff_chg {
  background-color: """
      + config.DIFF_COLOR_CHANGED
      + """;
  color: #000000;
  }
  .diff_sub {
  background-color: """
      + config.DIFF_COLOR_SUBTRACTED
      + """;
  color: #000000;
  }
  .diff_lineno {
  text-align: right;
  background-color: """
      + lineno_bg
      + """;
  color: #888888;
  }
  """
    )

  _row_template = """
  <tr>
    <td class="diff_lineno">%s</td>
    <td class="diff_play" nowrap width="48%%">%s</td>
    <td class="diff_lineno">%s</td>
    <td class="diff_play" nowrap width="48%%">%s</td>
  </tr>
  """

  _rexp_too_much_space = re.compile("^\t[.\\w]+ {8}")

  def make_file(self, lhs, rhs, fmt, lex):
    rows = []
    for left, right, changed in difflib._mdiff(lhs, rhs):
      lno, ltxt = left
      rno, rtxt = right

      if not changed:
        ltxt = highlight(ltxt, lex, fmt)
        rtxt = highlight(rtxt, lex, fmt)
      else:
        ltxt = self._stop_wasting_space(ltxt)
        rtxt = self._stop_wasting_space(rtxt)

        ltxt = ltxt.replace("<", "&lt;").replace(">", "&gt;")
        rtxt = rtxt.replace("<", "&lt;").replace(">", "&gt;")
        ltxt = ltxt.replace(" ", "&nbsp;")
        rtxt = rtxt.replace(" ", "&nbsp;")

      row = self._row_template % (str(lno), ltxt, str(rno), rtxt)
      rows.append(row)

    all_the_rows = "\n".join(rows)
    all_the_rows = (
      all_the_rows.replace("\x00+", '<span class="diff_add">')
      .replace("\x00-", '<span class="diff_sub">')
      .replace("\x00^", '<span class="diff_chg">')
      .replace("\x01", "</span>")
      .replace("\t", 4 * "&nbsp;")
    )

    res = self._html_template % {"style": self._style, "rows": all_the_rows}
    return res

  def _stop_wasting_space(self, s):
    """I never understood why you'd want to have 13 spaces between instruction and args'"""
    m = self._rexp_too_much_space.search(s)
    if m:
      mlen = len(m.group(0))
      return s[: mlen - 4] + s[mlen:]
    return s

#-------------------------------------------------------------------------------
def get_formatter(linenos=False):
  fmt = HtmlFormatter(style=get_style())
  fmt.noclasses = True
  fmt.linenos = linenos
  fmt.nobackground = True
  return fmt

#-------------------------------------------------------------------------------
def get_function_row(bd, ea, db_name, fields):
  cur = bd.db_cursor()
  try:
    sql = f"select {fields} from {db_name}.functions where address = ?"
    cur.execute(sql, (str(ea),))
    return cur.fetchone()
  finally:
    cur.close()

#-------------------------------------------------------------------------------
def generate_asm_diff(bd, ea1, ea2, field="assembly", html=True):
  """
  Generate the HTML diff of the assembly (or microcode) of the given functions.
  """
  row1 = get_function_row(bd, ea1, "main", f"name, {field}")
  row2 = get_function_row(bd, ea2, "diff", f"name, {field}")
  if row1 is None or row2 is None or row1[field] is None or row2[field] is None:
    warning(f"Sorry, there is no {field} available for either the first or the second database.")
    return None

  asm1 = bd.prettify_asm(row1[field])
  asm2 = bd.prettify_asm(row2[field])
  buf1 = f'{row1["name"]} proc near\n{asm1}\n{row1["name"]} endp'
  buf2 = f'{row2["name"]} proc near\n{asm2}\n{row2["name"]} endp'

  fmt = get_formatter()
  if not html:
    uni_diff = difflib.unified_diff(buf1.split("\n"), buf2.split("\n"))
    tmp = [line.strip("\n") for line in uni_diff][2:]
    return highlight("\n".join(tmp), DiffLexer(), fmt)
  return CHtmlDiff().make_file(buf1.split("\n"), buf2.split("\n"), fmt, NasmLexer())

#-------------------------------------------------------------------------------
def generate_pseudo_diff(bd, ea1, ea2, html=True):
  """
  Generate the HTML diff of the pseudo-code of the given functions.
  """
  row1 = get_function_row(bd, ea1, "main", "name, prototype, pseudocode")
  row2 = get_function_row(bd, ea2, "diff", "name, prototype, pseudocode")
  if row1 is None or row2 is None or row1["pseudocode"] is None or row2["pseudocode"] is None:
    warning("Sorry, there is no pseudo-code available for either the first or the second database.")
    return None

  buf1 = f'{row1["prototype"]}\n{row1["pseudocode"]}'
  buf2 = f'{row2["prototype"]}\n{row2["pseudocode"]}'
  if buf1 == buf2:
    log("Both pseudo-codes are equal.")

  fmt = get_formatter()
  if not html:
    uni_diff = difflib.unified_diff(buf1.split("\n"), buf2.split("\n"))
    tmp = [line.strip("\n") for line in uni_diff][2:]
    return highlight("\n".join(tmp), DiffLexer(), fmt)
  return CHtmlDiff().make_file(buf1.split("\n"), buf2.split("\n"), fmt, CppLexer())

#-------------------------------------------------------------------------------
def generate_function_source(bd, ea, db_name, pseudo):
  if pseudo:
    row = get_function_row(bd, ea, db_name, "name, prototype, pseudocode")
    if row is None or row["pseudocode"] is None:
      warning("Sorry, there is no pseudo-code available for the selected function.")
      return None
    src = f'{row["prototype"]}\n{row["pseudocode"]}'
    return highlight(src, CppLexer(), get_formatter(True)), f'Pseudo-code for {row["name"]}'

  row = get_function_row(bd, ea, db_name, "name, prototype, assembly")
  if row is None or row["assembly"] is None:
    warning("Sorry, there is no assembly available for the selected function.")
    return None
  asm = bd.prettify_asm(row["assembly"])
  src = f'; {row["prototype"]}\n{row["name"]} proc near\n{asm}\n{row["name"]} endp\n'
  return highlight(src, NasmLexer(), get_formatter(True)), f'Assembly for {row["name"]}'

#-------------------------------------------------------------------------------
@JImplements("ghidra.app.tablechooser.AddressableRowObject")
class CResultRow:
  """
  A row of a Diaphora's results table.
  """

  def __init__(self, item, address):
    self.item = item
    self.address = address

  @JOverride
  def getAddress(self):
    return self.address

  def get_ea1(self):
    return int(self.item[COL_EA1], 16)

  def get_ea2(self):
    return int(self.item[COL_EA2], 16)

#-------------------------------------------------------------------------------
@JImplements("ghidra.util.table.column.GColumnRenderer")
class CRowColorRenderer:
  """
  Cell renderer that paints the background of the match rows according to their
  ratio, like the IDA's choosers do.
  """

  def __init__(self):
    self.delegate = GTableCellRenderer()
    self.rendering_data = {}

  def get_rendering_data(self, table, column):
    """
    Return our own rendering data object for @column. The GTable's one is shared
    with the TableChooserDialog's renderer (which calls us) and the 6 arguments
    version of GTableCellRenderer.getTableCellRendererComponent() resets it.
    """
    key = (id(table), column)
    data = self.rendering_data.get(key)
    if data is None:
      data = GTableCellRenderingData(table, column, SettingsImpl.NO_SETTINGS)
      self.rendering_data[key] = data
    return data

  @JOverride
  def getTableCellRendererComponent(self, table, value, selected, focused, row, column):
    row_object = None
    try:
      row_object = table.getModel().getRowObject(row)
    except: # noqa: S110
      pass

    data = self.get_rendering_data(table, column)
    data.setRowData(row, row_object)
    data.setCellData(value, column, selected, focused)
    comp = self.delegate.getTableCellRendererComponent(data)

    if not selected and row_object is not None:
      try:
        comp.setBackground(get_row_color(row_object.item, table.getBackground()))
      except: # noqa: S110
        pass
    return comp

  @JOverride
  def getFilterString(self, value, settings):
    return "" if value is None else str(value)

#-------------------------------------------------------------------------------
@JImplements("ghidra.app.tablechooser.ColumnDisplay")
class CResultColumn:
  """
  A column of a Diaphora's results table.
  """

  def __init__(self, name, index, kind, renderer=None):
    self.name = name
    self.index = index
    self.kind = kind
    self.renderer = renderer

  def get_value(self, row):
    value = row.item[self.index]
    try:
      return self.kind(value)
    except (TypeError, ValueError):
      return self.kind()

  @JOverride
  def getColumnValue(self, row):
    value = self.get_value(row)
    if self.kind is float:
      # Shown with the same precision used by Diaphora (Ghidra shows Doubles with
      # 3 decimals), sorting is still numeric because it's done by compare().
      return JString(f"%.{config.DECIMAL_VALUES}" % value)
    if self.kind is int:
      return JInteger(value)
    return JString(str(value))

  @JOverride
  def getColumnName(self):
    return self.name

  @JOverride
  def getColumnClass(self):
    if self.kind is int:
      return JInteger.class_
    return JString.class_

  @JOverride
  def compare(self, row1, row2):
    val1 = self.get_value(row1)
    val2 = self.get_value(row2)
    return (val1 > val2) - (val1 < val2)

  @JOverride
  def equals(self, other):
    # java.util.Comparator re-declares equals() as abstract
    return self is other

  @JOverride
  def getRenderer(self):
    return self.renderer

#-------------------------------------------------------------------------------
@JImplements("ghidra.app.tablechooser.TableChooserExecutor")
class CImportExecutor:
  """
  The 'Import' button of the results tables.
  """

  def __init__(self, bindiff):
    self.bindiff = bindiff

  @JOverride
  def getButtonName(self):
    return "Import selected"

  @JOverride
  def execute(self, row):
    self.bindiff.import_items([(row.get_ea1(), row.get_ea2())], force=True)
    return False

  @JOverride
  def executeInBulk(self, rows, deleted, monitor):
    try:
      items = [(row.get_ea1(), row.get_ea2()) for row in rows]
      self.bindiff.import_items(items, force=True)
    except:
      log(f"Error importing results: {sys.exc_info()[1]}")
      traceback.print_exc()
    return True

#-------------------------------------------------------------------------------
class CGhidraChooser(diaphora.CChooser):
  """
  A Diaphora chooser shown in Ghidra as a TableChooserDialog.
  """

  def __init__(self, title, bindiff, show_commands=True):
    diaphora.CChooser.__init__(self, title, bindiff, show_commands)
    self.dialog = None
    self.tool = None

  def is_match_chooser(self):
    return not self.title.startswith("Unmatched in")

  def get_selected_rows(self):
    if self.dialog is None:
      return []
    return list(self.dialog.getSelectedRowObjects())

  def run_on_selected(self, func):
    """
    Run @func for the first selected row, showing any error to the user.
    """
    rows = self.get_selected_rows()
    if len(rows) == 0:
      warning("Please select a row first.")
      return

    try:
      func(rows[0])
    except:
      log(f"Error: {sys.exc_info()[1]}")
      traceback.print_exc()
      warning(str(sys.exc_info()[1]))

  def show_html(self, res, title):
    if res is not None:
      CHtmlViewer().show(res, title)

  def diff_asm(self, row):
    res = generate_asm_diff(self.bindiff, row.get_ea1(), row.get_ea2())
    self.show_html(res, f"Diff assembly {row.item[COL_NAME1]} - {row.item[COL_NAME2]}")

  def diff_microcode(self, row):
    res = generate_asm_diff(self.bindiff, row.get_ea1(), row.get_ea2(), field="microcode")
    self.show_html(res, f"Diff P-Code {row.item[COL_NAME1]} - {row.item[COL_NAME2]}")

  def diff_pseudo(self, row):
    res = generate_pseudo_diff(self.bindiff, row.get_ea1(), row.get_ea2())
    self.show_html(res, f"Diff pseudo-code {row.item[COL_NAME1]} - {row.item[COL_NAME2]}")

  def show_source(self, row, pseudo):
    db_name = "main" if self.primary else "diff"
    res = generate_function_source(self.bindiff, row.get_ea1(), db_name, pseudo)
    if res is not None:
      self.show_html(*res)

  def save_results(self):
    # pylint: disable=import-error
    from docking.widgets.filechooser import GhidraFileChooser
    # pylint: enable=import-error
    chooser = GhidraFileChooser(None)
    chooser.setTitle("Save Diaphora results")
    chooser.setApproveButtonText("Save")
    selected = chooser.getSelectedFile()
    chooser.dispose()
    if selected is None:
      return

    filename = str(selected.getAbsolutePath())
    if not filename.endswith(".diaphora"):
      filename += ".diaphora"
    self.bindiff.save_results(filename)

  def highlight_functions(self, highlight=True):
    """
    Set (or clear) the background colour of all the functions in this chooser.
    """
    colorizer = None
    if self.tool is not None:
      colorizer = self.tool.getService(ColorizingService)
    if colorizer is None:
      warning("The colorizing service is not available.")
      return

    color = get_highlight_color(self.get_color())
    program = self.bindiff.program
    funcman = program.getFunctionManager()
    total = 0
    tx = program.startTransaction("Diaphora: highlight matches")
    try:
      for item in self.items:
        func = funcman.getFunctionAt(self.bindiff.to_addr(int(item[COL_EA1], 16)))
        if func is None:
          continue

        if highlight:
          colorizer.setBackgroundColor(func.getBody(), color)
        else:
          colorizer.clearBackgroundColor(func.getBody())
        total += 1
    finally:
      program.endTransaction(tx, True)

    action = "highlighted" if highlight else "unhighlighted"
    log(f"{total} function(s) {action}.")

  def add_action(self, name, callback, pass_row=True):
    if pass_row:
      on_action = lambda ctx: self.run_on_selected(callback)
    else:
      on_action = lambda ctx: callback()

    # Action names cannot contain consecutive dots (they are used as delimiters
    # of the key bindings options), but menu entries can.
    action = (
      ActionBuilder(name.rstrip("."), OWNER)
      .popupMenuPath([name])
      .onAction(on_action)
      .enabledWhen(lambda ctx: True)
      .build()
    )
    self.dialog.addAction(action)

  def create_dialog(self, script):
    executor = None
    if self.is_match_chooser():
      executor = CImportExecutor(self.bindiff)

    title = f"Diaphora: {self.title}"
    self.dialog = script.createTableChooserDialog(title, executor, False)
    self.tool = script.getState().getTool()

    if self.is_match_chooser():
      renderer = CRowColorRenderer()
      for name, index, kind in MATCH_COLUMNS:
        self.dialog.addCustomColumn(CResultColumn(name, index, kind, renderer))
      self.add_action("Diff assembly", self.diff_asm)
      self.add_action("Diff pseudo-code", self.diff_pseudo)
      self.add_action("Diff P-Code (microcode)", self.diff_microcode)
      if self.get_color() is not None:
        self.add_action("Highlight matches", lambda: self.highlight_functions(True), False)
        self.add_action("Unhighlight matches", lambda: self.highlight_functions(False), False)
      self.add_action("Save results...", self.save_results, False)
      self.dialog.setMessage("Double click to navigate, right click to see the diffs.")
    else:
      for name, index, kind in UNMATCHED_COLUMNS:
        self.dialog.addCustomColumn(CResultColumn(name, index, kind))
      self.add_action("Show assembly", lambda row: self.show_source(row, False))
      self.add_action("Show pseudo-code", lambda row: self.show_source(row, True))
      self.add_action("Save results...", self.save_results, False)

    # The same pair can be found by more than one heuristic using different
    # names for the functions (mangled and demangled), show it only once.
    to_addr = self.bindiff.to_addr
    dones = set()
    for item in self.items:
      key = (item[COL_EA1], item[COL_EA2]) if self.is_match_chooser() else item[COL_EA1]
      if key in dones:
        continue
      dones.add(key)
      self.dialog.add(CResultRow(item, to_addr(int(item[COL_EA1], 16))))

    if self.is_match_chooser():
      # Sort by the ratio column (the first column is the address)
      self.dialog.setSortState(TableSortState.createDefaultSortState(4, False))

  def show(self, force=False):
    script = diaphora_ghidra.g_script
    if script is None or script.isRunningHeadless():
      return

    if self.dialog is None or force:
      self.create_dialog(script)
    self.dialog.show()
    g_windows.append(self)

#-------------------------------------------------------------------------------
def show_choosers(bd):
  """
  Show all the non empty choosers.
  """
  choosers = [
    bd.best_chooser,
    bd.partial_chooser,
    bd.multimatch_chooser,
    bd.unreliable_chooser,
    bd.unmatched_primary,
    bd.unmatched_second,
  ]

  if config.ML_DEBUG_SHOW_MATCHES:
    choosers.append(bd.ml_chooser)

  for chooser in choosers:
    if chooser is not None and len(chooser.items) > 0:
      chooser.show()
