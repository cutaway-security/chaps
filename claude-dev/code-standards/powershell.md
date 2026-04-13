# PowerShell Code Standards

## Version Compatibility

- Always check PowerShell version first before using version-dependent features
- Use `$PSVersionTable.PSVersion` for detection
- Gate features behind version checks when targeting mixed environments
- Document minimum required version at the top of each script

## Parameter Handling

- Use `[CmdletBinding()]` on all functions and scripts
- Use `[Parameter()]` attributes with validation (ValidateSet, ValidateRange, ValidateNotNullOrEmpty)
- Use `Verb-Noun` naming convention for all functions

## Error Handling

- Use try/catch/finally for operations that can fail
- Understand scope: `$ErrorActionPreference` affects the entire session; `-ErrorAction Stop` is scoped to a single cmdlet -- prefer `-ErrorAction Stop` on individual cmdlets
- Log errors with `Write-Error` or `Write-Warning` -- never swallow silently
- Use finally blocks to clean up resources (close files, release handles)

## WMI and CIM

- Prioritize WMI (`Get-WmiObject`) for maximum backward compatibility on older systems
- Use CIM (`Get-CimInstance`) when targeting PowerShell 3.0+ environments
- Gate CIM usage behind version checks if script must run on PowerShell 2.0

## Output

- `Write-Output` for pipeline data (can be captured, piped, assigned)
- `Write-Host` only for user-facing display that should never be captured
- `Write-Warning` and `Write-Error` for diagnostics
- Never use `Format-*` cmdlets (`Format-Table`, `Format-List`) in the middle of a pipeline -- they destroy objects and return format instructions, not data. Only use `Format-*` as the final command for display.

## Silent Error Logging

When collecting errors without console output:

```powershell
try {
    Some-Operation -ErrorAction Stop
} catch {
    $script:errors += $_.Exception.Message
    # Continue execution without console output
}
```

## Common Pitfalls

### Variable Scope in Loops

Variables assigned inside `ForEach-Object` or script blocks may not be visible outside. Use `$script:` or `$global:` scope, or collect results via pipeline assignment.

### String vs Object Comparison

`-eq` on objects compares by value for strings and numbers but by reference for complex objects. Use `.Equals()` or compare specific properties.

### Execution Policy

Scripts may fail silently on systems with restricted execution policy. Document that users may need `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`.

## Script Structure

- Include comment-based help (`<# .SYNOPSIS ... #>`) at the top
- Define parameters with CmdletBinding
- Validate environment early (check required modules, OS version, privilege level)
- Return meaningful exit codes (0 = success, non-zero = failure)
