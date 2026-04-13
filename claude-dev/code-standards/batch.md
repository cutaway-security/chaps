# Batch Script Code Standards

## General

- Use `@echo off` at the start of every script
- Use `SETLOCAL` to prevent variable leakage to the calling environment
- Return meaningful exit codes via `exit /b <code>`

## Variable Expansion

### Delayed Expansion

Inside parenthesized blocks (if/else, for loops), variables set with `set` are expanded at parse time, not runtime. Use delayed expansion:

```batch
SETLOCAL ENABLEDELAYEDEXPANSION
for %%F in (*.txt) do (
    set "FILENAME=%%~nF"
    echo !FILENAME!
)
```

Use `!VAR!` inside blocks, `%VAR%` outside. Forgetting this is the most common batch scripting bug.

## Redirection Safety

### Never use `>` inside echo within parenthesized blocks

This creates orphaned files:

```batch
REM BAD -- creates a file named "Properties)" on disk
if defined RESULT (
    echo Registry Properties > "%OUTPUT%"
)
```

Fix: assign the string to a variable first, then echo outside the block, or use delayed expansion with careful quoting.

### Always quote redirect targets

```batch
REM BAD
echo data > %FILEPATH%

REM GOOD
echo data > "%FILEPATH%"
```

Unquoted paths with spaces create orphaned files with partial names.

### Check git status after running batch scripts

Batch redirection bugs silently create files. Always run `git status` after testing to catch orphaned files.

## Numeric vs String Comparison

`if` comparisons using `GEQ`, `GTR`, `LSS`, `LEQ`, `EQU` perform string comparison by default. For numeric comparison, convert first:

```batch
REM BAD -- string comparison: "9" > "10" because "9" > "1"
if "%BUILD%" GEQ "10000" (echo Modern)

REM GOOD -- numeric comparison
set /a BUILD_NUM=%BUILD%
if %BUILD_NUM% GEQ 10000 (echo Modern)
```

This is a critical bug source for any version or build number comparisons.

## Error Handling

- Check `%ERRORLEVEL%` after operations that can fail
- Use `if errorlevel 1` or `if %ERRORLEVEL% NEQ 0` patterns
- Provide meaningful error messages before exiting

## File and Path Handling

- Always quote paths: `"%FILEPATH%"`
- Use `~` modifiers for parameter expansion: `%%~nF` (name), `%%~xF` (extension), `%%~dpF` (drive+path)
- Check file existence before operations: `if exist "%FILE%"`

## Functions

- Define functions with `:FunctionName` labels
- Call with `call :FunctionName args`
- Return values via `set` or exit codes
- Use `goto :eof` or `exit /b` to return from functions

## Common Pitfalls

- `set "VAR=value"` (quotes outside) prevents trailing spaces
- `for /f` tokens default to space and tab delimiters -- specify `delims=` explicitly when parsing structured data
- `enabledelayedexpansion` must be set before the block that needs it, not inside it
- Pipe (`|`) creates subshells -- variables set in piped commands are lost
