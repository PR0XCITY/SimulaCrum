<#
.SYNOPSIS
  terraform apply, but only with a GhostOps approval. Sample wrapper for this repo's demos.

.DESCRIPTION
  1. Refuses any directory outside this repo's demo\ folder, and any MiniStack endpoint that
     is not on loopback. Writes the GhostOps MiniStack override file (every AWS endpoint forced
     to MiniStack, fake keys) and removes every AWS_* variable from this process.
  2. terraform init, plan -out (a saved plan), show -json of that saved plan.
  3. python -m app.gate decide: gets the signed certificate for exactly that plan (a stored one
     is reused so a reviewer's decision counts) and decides.
  4. Applies the saved plan only if the certificate is AUTO_APPROVED, or BLOCKED_PENDING_REVIEW
     with an approve decision in the audit log. Otherwise it stops and keeps the saved plan;
     approve it in the dashboard and run again with -Resume to apply that same plan.

  This is a demo of the gate, not a production deploy tool. It can only target MiniStack.
  Using the idea against a real cloud account needs your own review of the guards, the
  credentials and the approval process.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\safe-apply.ps1 -TfDir demo\good
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\safe-apply.ps1 -TfDir demo\bad -Resume
#>
param(
    [string]$TfDir = "demo\good",
    [switch]$Resume,
    [switch]$NoGroq
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$Py = Join-Path $Root ".venv\Scripts\python.exe"
if (-not (Test-Path $Py)) { Write-Error "Python venv not found at $Py (see README setup)"; exit 2 }
if (-not (Get-Command terraform -ErrorAction SilentlyContinue)) { Write-Error "terraform not found on PATH"; exit 2 }
if (-not (Test-Path $TfDir -PathType Container)) { Write-Error "not a directory: $TfDir"; exit 2 }
$Dir = (Resolve-Path $TfDir).Path

function Say([string]$Text) { Write-Host "[safe-apply] $Text" }

# 1. Guards (Python, so the same checks are unit-tested) + MiniStack override file.
$Override = & $Py -m app.gate prepare-apply --tf $Dir
if ($LASTEXITCODE -ne 0) { Say "refused before planning."; exit 2 }

# No real AWS credentials can reach terraform: drop every AWS_* variable, then set fake ones.
Get-ChildItem Env: | Where-Object { $_.Name -like "AWS_*" } | ForEach-Object { Remove-Item "Env:$($_.Name)" }
$Empty = Join-Path $env:TEMP "ghostops-empty-aws-file"
Set-Content -Path $Empty -Value "" -Encoding ascii
$env:AWS_ACCESS_KEY_ID = "test"
$env:AWS_SECRET_ACCESS_KEY = "test"
$env:AWS_DEFAULT_REGION = "us-east-1"
$env:AWS_REGION = "us-east-1"
$env:AWS_SHARED_CREDENTIALS_FILE = $Empty
$env:AWS_CONFIG_FILE = $Empty
$env:AWS_EC2_METADATA_DISABLED = "true"
$env:AWS_ENDPOINT_URL = "http://localhost:4566"
$env:TF_IN_AUTOMATION = "1"
$env:TF_INPUT = "0"
$env:TF_PLUGIN_CACHE_DIR = Join-Path $Root ".terraform-plugin-cache"
New-Item -ItemType Directory -Force $env:TF_PLUGIN_CACHE_DIR | Out-Null

$Work = Join-Path $Dir ".ghostops-apply"
$PlanFile = Join-Path $Work "apply.tfplan"
$PlanJson = Join-Path $Work "plan.json"
$Code = 2
try {
    # 2. A saved plan: what gets certified is exactly what gets applied.
    terraform "-chdir=$Dir" init -input=false -no-color | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "terraform init failed" }
    if ($Resume) {
        if (-not (Test-Path $PlanFile)) { throw "-Resume: no saved plan at $PlanFile; run without -Resume first" }
        Say "reusing the saved plan from the previous run"
    } else {
        New-Item -ItemType Directory -Force $Work | Out-Null
        terraform "-chdir=$Dir" plan -input=false -no-color "-out=$PlanFile"
        if ($LASTEXITCODE -ne 0) { throw "terraform plan failed" }
    }
    $Shown = terraform "-chdir=$Dir" show -json -no-color $PlanFile
    if ($LASTEXITCODE -ne 0) { throw "terraform show failed" }
    [System.IO.File]::WriteAllText($PlanJson, ($Shown -join "`n"), (New-Object System.Text.UTF8Encoding $false))

    # 3. GhostOps decides.
    Say "asking GhostOps (a new plan takes 1-2 minutes: policy, shadow apply, cost)..."
    $GateArgs = @("-m", "app.gate", "decide", "--plan", $PlanJson, "--tf", $Dir)
    if ($NoGroq) { $GateArgs += "--no-groq" }
    $Decision = & $Py @GateArgs
    $Code = $LASTEXITCODE
    $Decision | Write-Host
    if ($Code -eq 1) {
        $Result = ($Decision -join "`n") | ConvertFrom-Json
        Say "REFUSED: $($Result.reason)"
        Say "review it at $($Result.dashboard_url), then run again with -Resume to apply this same plan."
        exit 1
    }
    if ($Code -ne 0) { throw "GhostOps could not decide (exit $Code); nothing applied" }

    # 4. Approved: apply the saved, certified plan (MiniStack only).
    Say "approved; applying the certified plan to MiniStack"
    terraform "-chdir=$Dir" apply -input=false -no-color $PlanFile
    if ($LASTEXITCODE -ne 0) { throw "terraform apply failed" }
    Remove-Item -Recurse -Force $Work
    Say "applied."
    exit 0
} catch {
    Say "ERROR: $($_.Exception.Message)"
    exit 2
} finally {
    if ($Override -and (Test-Path $Override)) { Remove-Item -Force $Override }
}
