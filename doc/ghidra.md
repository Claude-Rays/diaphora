# Diaphora for Ghidra (PyGhidra)

Diaphora can export, diff and show results from inside Ghidra using
[PyGhidra](https://github.com/NationalSecurityAgency/ghidra/tree/master/Ghidra/Features/PyGhidra),
Ghidra's native CPython 3 support. The diffing engine (`diaphora.py`,
`diaphora_heuristics.py`, the ML model, etc.) is exactly the same one used with
IDA: only the exporter and the user interface are Ghidra specific.

> **Note:** So far the port has only been tested on Windows, with Ghidra 12.2
> (PyGhidra 3.2, Python 3.13). Older Ghidra versions with PyGhidra (11.3+),
> Linux and macOS are untested.

| File | Description |
|------|-------------|
| `diaphora_ghidra.py` | Exporter (`CGhidraBinDiff`), results loading and importing. |
| `diaphora_ghidra_ui.py` | Results tables, diff viewers and the import button. |
| `ghidra_scripts/DiaphoraExportOrDiff.py` | `Tools > Diaphora > Export or diff` (GUI and headless). |
| `ghidra_scripts/DiaphoraLoadResults.py` | `Tools > Diaphora > Load results`. |

## Installation

1. Start Ghidra with PyGhidra support (`support\pyghidraRun.bat` on Windows,
   `support/pyghidraRun` elsewhere, or the *PyGhidra* entry of the launcher).
2. Open a program in the CodeBrowser, then `Window > Script Manager`.
3. Click *Manage Script Directories* and add the `ghidra_scripts` directory of
   this repository. The scripts must stay inside this repository: they load
   Diaphora from the parent directory (or from the directory pointed to by the
   `DIAPHORA_DIR` environment variable).
4. The menu entries `Tools > Diaphora > Export or diff` and
   `Tools > Diaphora > Load results` will appear. The scripts are also listed
   in the Script Manager under the `Diaphora` category.

Optional Python libraries, installed into the PyGhidra virtual environment
(by default `%APPDATA%\ghidra\ghidra_<version>\venv`, or
`~/.config/ghidra/ghidra_<version>/venv`):

    <venv>/Scripts/python -m pip install cdifflib scikit-learn joblib pandas numpy

`cdifflib` makes text diffing faster and `scikit-learn`, `joblib`, `pandas` and
`numpy` are required to use the trained ML model. Diaphora works without them.

## Usage

The workflow is the same one used with IDA:

1. Open the *secondary* binary (e.g., the old version), run
   `Tools > Diaphora > Export or diff` and export it to a `.sqlite` database.
2. Open the *primary* binary (e.g., the patched version), run the same script,
   select where to export it and, in *Diff against*, the database exported in
   the previous step.
3. When the diff finishes, one table per category is shown (*Best matches*,
   *Partial matches*, *Unreliable matches*, *Problematic matches*, *Unmatched in
   primary* and *Unmatched in secondary*):
   * As in IDA, the rows of the matches are coloured according to their ratio
     (from green to purple) and in orange when the match seems a false positive.
   * Double click a row to navigate to the function in the current program.
   * Right click a row to see the assembly, pseudo-code or P-Code diffs, to
     highlight (or unhighlight) the matched functions in the listing using the
     `HIGHLIGHT_FUNCTION_*` colours of `diaphora_config.py`, or to save the
     results to a `.diaphora` file.
   * *Import selected* renames the selected functions using the names (and
     function comments) from the secondary database.

Previously saved results can be shown again with `Tools > Diaphora > Load
results`.

## Headless usage

Export a program (and, optionally, diff it) with `pyghidraRun -H`, which
accepts the same arguments as `analyzeHeadless`. For a program that is already
analyzed in a project:

    support\pyghidraRun.bat -H <project_dir> <project_name> -process urlmon.dll -noanalysis ^
      -scriptPath <diaphora>\ghidra_scripts ^
      -postScript DiaphoraExportOrDiff.py urlmon.sqlite [old-urlmon.sqlite [results.diaphora]]

Use `-import <binary>` instead of `-process <program> -noanalysis` to import
and analyze a new binary first.

Or from Python using the `pyghidra` package:

```python
import pyghidra
pyghidra.start()
pyghidra.run_script("urlmon.dll", "ghidra_scripts/DiaphoraExportOrDiff.py",
                    project_location="projects", project_name="diffing",
                    script_args=["urlmon.sqlite", "old-urlmon.sqlite"])
```

When a database to diff against is given and no results file is specified, the
results are saved to `<export>_vs_<diff>.diaphora`. Some options can be set
using environment variables: `DIAPHORA_EXPORT_FILE`, `DIAPHORA_USE_DECOMPILER`,
`DIAPHORA_EXPORT_MICROCODE`, `DIAPHORA_EXCLUDE_LIBRARY_THUNK`,
`DIAPHORA_FUNCTION_SUMMARIES_ONLY`, `DIAPHORA_PROJECT_SCRIPT`,
`DIAPHORA_FROM_ADDRESS` and `DIAPHORA_TO_ADDRESS` (hexadecimal). The diffing
options of `diaphora.py` (`DIAPHORA_CPU_COUNT`, `DIAPHORA_SQL_TIMEOUT_LIMIT`,
etc.) work as usual.

Two exported databases can also be diffed from the command line, without
Ghidra or IDA:

    python diaphora.py urlmon.sqlite old-urlmon.sqlite -o results.diaphora

## Differences with the IDA exporter

* **Names**: the heuristics expect IDA's auto-generated names, so Ghidra's
  default names are translated when exporting: `FUN_` becomes `sub_`,
  `thunk_FUN_` becomes `j_sub_`, `LAB_` becomes `loc_`, `DAT_` becomes `unk_`,
  `PTR_` becomes `off_`, `switchD_` becomes `jpt_` and strings like
  `s_Hello_00401000` become `aHello`. Variable names that change between builds
  (`local_10`, `iVar1`, `param_1`...) are ignored when comparing assembly and
  pseudo-code.
* **Repeated names**: Ghidra allows different functions with the same name
  (IDA doesn't), but the diffing engine indexes matches by name, so repeated
  names get an ordinal suffix (`name_1`, `name_2`...) in address order.
* **Pseudo-code**: generated with Ghidra's decompiler. The "AST hash" is the
  product of the primes assigned to the high level P-Code operations.
* **Microcode**: Hex-Rays' microcode is replaced by Ghidra's high level P-Code.
  It is exported by default only for databases with less than
  `MIN_FUNCTIONS_TO_CONSIDER_MEDIUM` functions.
* **Function flags**: emulated (`noreturn`, thunk, and library when the function
  has a tag containing `LIBRARY`).
* **Forced operands**: Ghidra's equates are exported instead.
* **Mnemonics SPP**: Ghidra doesn't expose the list of instructions of a
  processor, so the prime of each mnemonic is derived from its CRC32.
* **Not supported (yet)**: compilation units (CodeCut/LFA), exporting and
  importing structures/enumerations, type libraries and instruction level
  imports. Importing results only imports function names and comments.

Databases exported from Ghidra and IDA use the same schema. Diffing a Ghidra
database against an IDA one was tested once, with two builds of `urlmon.dll`
and `diaphora.py` from the command line: it worked and matched 88% of the
functions, but almost all of them as partial matches, because the disassembly
syntax, the decompilers and many other details differ. Diffing two databases
exported with the same tool gives much better results.

The decompiler timeout per function can be changed with
`GHIDRA_DECOMPILER_TIMEOUT` in `diaphora_config.py`.
