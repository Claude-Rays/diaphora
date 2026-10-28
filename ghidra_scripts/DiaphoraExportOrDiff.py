# Diaphora: export the current program to a Diaphora database and, optionally,
# diff it against another Diaphora database (exported from Ghidra or IDA).
#
# Headless usage (arguments are optional, environment variables DIAPHORA_* are
# honoured too):
#   DiaphoraExportOrDiff.py <export.sqlite> [<diff_against.sqlite> [<results.diaphora>]]
# @author ClaudeMonkey, PyGhidra port of Diaphora by Joxean Koret
# @category Diaphora
# @menupath Tools.Diaphora.Export or diff
# @runtime PyGhidra

"""
Diaphora's PyGhidra script: export & diff.
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
  """
  Diaphora lives in the parent directory of the ghidra_scripts one, unless the
  environment variable DIAPHORA_DIR says otherwise.
  """
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
from java.io import File
from ghidra.features.base.values import GhidraValuesMap
from ghidra.util.exception import CancelledException

import diaphora_ghidra
from diaphora_ghidra import log, CDiaphoraOptions
# pylint: enable=wrong-import-position,import-error

#-------------------------------------------------------------------------------
OPT_FILE_OUT = "Export current program to"
OPT_FILE_IN = "Diff against (optional)"
OPT_RESULTS = "Save diff results to (optional)"
OPT_SCRIPT = "Project specific script (optional)"

BOOLEAN_OPTIONS = [
  ("use_decompiler", "Use the decompiler"),
  ("export_microcode", "Export P-Code as microcode (slow)"),
  ("exclude_library_thunk", "Exclude library and thunk functions"),
  ("func_summaries_only", "Export only function summaries"),
  ("unreliable", "Use probably unreliable methods"),
  ("slow", "Use slow heuristics"),
  ("relax", "Relaxed calculations of difference ratios"),
  ("experimental", "Use experimental heuristics"),
  ("use_trained_model", "Use the trained ML model (requires scikit-learn)"),
  ("ignore_sub_names", "Ignore automatically generated names"),
  ("ignore_all_names", "Ignore all function names"),
  ("ignore_small_functions", "Ignore small functions"),
]

#-------------------------------------------------------------------------------
def get_path(values, name):
  f = values.getFile(name)
  if f is None:
    return ""
  return str(f.getAbsolutePath())

#-------------------------------------------------------------------------------
def ask_options(opts):
  values = GhidraValuesMap()
  values.defineFile(OPT_FILE_OUT, File(opts.file_out))
  values.defineFile(OPT_FILE_IN, None)
  values.defineFile(OPT_RESULTS, None)
  for key, label in BOOLEAN_OPTIONS:
    values.defineBoolean(label, bool(getattr(opts, key)))
  values.defineFile(OPT_SCRIPT, None)

  msg = "Export the current program and, optionally, diff it against another Diaphora database."
  values = askValues("Diaphora", msg, values)

  opts.file_out = get_path(values, OPT_FILE_OUT)
  opts.file_in = get_path(values, OPT_FILE_IN)
  opts.results_file = get_path(values, OPT_RESULTS)
  opts.project_script = get_path(values, OPT_SCRIPT) or None
  for key, label in BOOLEAN_OPTIONS:
    setattr(opts, key, values.getBoolean(label))
  return opts

#-------------------------------------------------------------------------------
def get_default_results_file(file_out, file_in):
  path1 = os.path.splitext(file_out)[0]
  path2 = os.path.basename(os.path.splitext(file_in)[0])
  return f"{path1}_vs_{path2}.diaphora"

#-------------------------------------------------------------------------------
def get_env_bool(name, default):
  value = os.getenv(f"DIAPHORA_{name.upper()}")
  if value is None:
    return bool(default)
  return value.lower() not in ["0", "false", "no", "off", ""]

#-------------------------------------------------------------------------------
def run_headless():
  args = list(getScriptArgs())
  opts = CDiaphoraOptions(currentProgram)
  opts.use_decompiler = get_env_bool("use_decompiler", opts.use_decompiler)
  opts.export_microcode = get_env_bool("export_microcode", opts.export_microcode)
  opts.exclude_library_thunk = get_env_bool("exclude_library_thunk", opts.exclude_library_thunk)
  opts.func_summaries_only = get_env_bool("function_summaries_only", opts.func_summaries_only)

  opts.file_out = os.getenv("DIAPHORA_EXPORT_FILE", opts.file_out)
  if len(args) > 0:
    opts.file_out = args[0]
  if len(args) > 1:
    opts.file_in = args[1]
  if len(args) > 2:
    opts.results_file = args[2]
  elif opts.file_in != "":
    opts.results_file = get_default_results_file(opts.file_out, opts.file_in)

  project_script = os.getenv("DIAPHORA_PROJECT_SCRIPT")
  if project_script is not None:
    opts.project_script = project_script

  log(f"Exporting {currentProgram.getName()} to {opts.file_out}")
  diaphora_ghidra.export_and_diff(currentProgram, opts, monitor)

#-------------------------------------------------------------------------------
def run_gui():
  # pylint: disable=import-error
  import diaphora_ghidra_ui
  # pylint: enable=import-error

  opts = ask_options(CDiaphoraOptions(currentProgram))
  if opts.file_out == "" or len(opts.file_out) < 5:
    popup("No output database selected or invalid filename. Please select a database file.")
    return

  if opts.file_out == opts.file_in:
    popup("Both databases are the same file!")
    return

  export = True
  resume_crashed = False
  if os.path.exists(opts.file_out):
    crash_file = f"{opts.file_out}-crash"
    if os.path.exists(crash_file):
      resume_crashed = askYesNo(
        "Diaphora",
        "The previous export session crashed. Do you want to resume the previous crashed session?",
      )

    if not resume_crashed:
      export = askYesNo(
        "Diaphora",
        "Export database already exists. Do you want to overwrite it?\n\n"
        "Choose 'No' to use the existing database for diffing.",
      )

  bd = diaphora_ghidra.export_and_diff(
    currentProgram, opts, monitor, chooser=diaphora_ghidra_ui.CGhidraChooser,
    export=export, resume_crashed=resume_crashed, ask_yes_no=askYesNo
  )

  if opts.file_in != "":
    diaphora_ghidra_ui.show_choosers(bd)

#-------------------------------------------------------------------------------
def main():
  diaphora_ghidra.set_script(this, monitor)
  try:
    if isRunningHeadless():
      run_headless()
    else:
      run_gui()
  except (diaphora_ghidra.CDiaphoraCancelled, CancelledException):
    log("Cancelled.")

main()
