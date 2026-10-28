# Diaphora: load and show previously saved diffing results (.diaphora files).
# The primary database must have been exported from the current program.
# @author ClaudeMonkey, PyGhidra port of Diaphora by Joxean Koret
# @category Diaphora
# @menupath Tools.Diaphora.Load results
# @runtime PyGhidra

"""
Diaphora's PyGhidra script: load results.
Copyright (c) 2015-2026 Joxean Koret
Copyright (c) 2026 ClaudeMonkey (PyGhidra port)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.
"""

import os
import sys
import typing

if typing.TYPE_CHECKING:
  from ghidra.ghidra_builtins import *  # pylint: disable=wildcard-import

#-------------------------------------------------------------------------------
def get_diaphora_dir():
  path = os.getenv("DIAPHORA_DIR")
  if path is None:
    try:
      script_path = __file__
    except NameError:
      script_path = str(getSourceFile().getAbsolutePath())
    path = os.path.dirname(os.path.dirname(os.path.realpath(script_path)))
  return path

DIAPHORA_DIR = get_diaphora_dir()
if DIAPHORA_DIR not in sys.path:
  sys.path.insert(0, DIAPHORA_DIR)

# pylint: disable=wrong-import-position,import-error
from ghidra.util.exception import CancelledException

import diaphora_ghidra
import diaphora_ghidra_ui
# pylint: enable=wrong-import-position,import-error

#-------------------------------------------------------------------------------
def ask_database(title, filename):
  try:
    f = askFile(f"{title} ({os.path.basename(filename)})", "Select")
  except CancelledException:
    return None
  return str(f.getAbsolutePath())

#-------------------------------------------------------------------------------
def main():
  diaphora_ghidra.set_script(this, monitor)
  if isRunningHeadless():
    diaphora_ghidra.log("This script can only be used from the Ghidra's GUI.")
    return

  try:
    results = askFile("Select the Diaphora results file", "Load")
  except CancelledException:
    return
  filename = str(results.getAbsolutePath())

  bd = diaphora_ghidra.CGhidraBinDiff(
    ":memory:", program=currentProgram, monitor=monitor,
    chooser=diaphora_ghidra_ui.CGhidraChooser
  )
  if not bd.load_results(filename, ask_file=ask_database):
    popup(f"Error loading the results file {os.path.basename(filename)}")
    return

  diaphora_ghidra.log("Showing diff results.")
  diaphora_ghidra_ui.show_choosers(bd)

main()
