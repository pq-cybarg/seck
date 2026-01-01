# Seck.psm1 — PowerShell wrapper for users who don't want to invoke the
# shellext via right-click. Forwards $Path to seck.exe analyze.

function Invoke-Seck {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [string]$Path,

        [ValidateSet('a', 'b')]
        [string]$SandboxMode = 'a',

        [ValidateSet('json', 'terminal')]
        [string]$Output = 'json'
    )
    process {
        & seck.exe analyze $Path --sandbox-mode=$SandboxMode --output=$Output
    }
}

Export-ModuleMember -Function Invoke-Seck
