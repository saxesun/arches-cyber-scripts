[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$moduleRoot = Join-Path $PSScriptRoot 'Modules'
@('Results.psm1','Diagnostics.psm1','Rollback.psm1','Remediation.psm1') | ForEach-Object {
    Import-Module (Join-Path $moduleRoot $_) -Force -ErrorAction Stop
}

$rollbackDirectory = Join-Path $PSScriptRoot 'Rollback'
$script:currentPlan = $null

$form = New-Object Windows.Forms.Form
$form.Text = 'Arches Cyber Guided Fixes'
$form.Size = New-Object Drawing.Size(900, 700)
$form.MinimumSize = New-Object Drawing.Size(780, 620)
$form.StartPosition = 'CenterScreen'
$form.Font = New-Object Drawing.Font('Segoe UI', 10)

$title = New-Object Windows.Forms.Label
$title.Text = 'Guided Fixes'
$title.Font = New-Object Drawing.Font('Segoe UI Semibold', 20)
$title.AutoSize = $true
$title.Location = New-Object Drawing.Point(24, 18)
$form.Controls.Add($title)

$intro = New-Object Windows.Forms.Label
$intro.Text = 'Select an approved remediation, review its exact plan, then approve only that displayed change.'
$intro.AutoSize = $true
$intro.Location = New-Object Drawing.Point(27, 62)
$form.Controls.Add($intro)

$fixLabel = New-Object Windows.Forms.Label
$fixLabel.Text = 'Approved remediation'
$fixLabel.AutoSize = $true
$fixLabel.Location = New-Object Drawing.Point(27, 100)
$form.Controls.Add($fixLabel)

$fixPicker = New-Object Windows.Forms.ComboBox
$fixPicker.DropDownStyle = 'DropDownList'
$fixPicker.Location = New-Object Drawing.Point(30, 124)
$fixPicker.Size = New-Object Drawing.Size(560, 30)
$catalog = @(Get-ArchesRemediationCatalog)
foreach ($item in $catalog) {
    [void]$fixPicker.Items.Add("$($item.Id) - $($item.Title)")
}
if ($fixPicker.Items.Count) { $fixPicker.SelectedIndex = 0 }
$form.Controls.Add($fixPicker)

$attestation = New-Object Windows.Forms.CheckBox
$attestation.Text = 'I verified that no unsupported management product owns Windows Firewall policy.'
$attestation.AutoSize = $true
$attestation.Location = New-Object Drawing.Point(30, 164)
$form.Controls.Add($attestation)

$planButton = New-Object Windows.Forms.Button
$planButton.Text = 'Build Read-Only Plan'
$planButton.Location = New-Object Drawing.Point(620, 122)
$planButton.Size = New-Object Drawing.Size(220, 34)
$form.Controls.Add($planButton)

$planBox = New-Object Windows.Forms.RichTextBox
$planBox.ReadOnly = $true
$planBox.BackColor = [Drawing.Color]::White
$planBox.Font = New-Object Drawing.Font('Consolas', 10)
$planBox.Location = New-Object Drawing.Point(30, 205)
$planBox.Size = New-Object Drawing.Size(810, 325)
$planBox.Anchor = 'Top,Bottom,Left,Right'
$planBox.Text = "No plan has been built. No configuration changes can run until a current plan is displayed."
$form.Controls.Add($planBox)

$approval = New-Object Windows.Forms.CheckBox
$approval.Text = 'I reviewed and approve this exact displayed change.'
$approval.AutoSize = $true
$approval.Enabled = $false
$approval.Location = New-Object Drawing.Point(30, 550)
$approval.Anchor = 'Bottom,Left'
$form.Controls.Add($approval)

$runButton = New-Object Windows.Forms.Button
$runButton.Text = 'Run Approved Change'
$runButton.Enabled = $false
$runButton.Location = New-Object Drawing.Point(620, 585)
$runButton.Size = New-Object Drawing.Size(220, 42)
$runButton.Anchor = 'Bottom,Right'
$form.Controls.Add($runButton)

$closeButton = New-Object Windows.Forms.Button
$closeButton.Text = 'Close'
$closeButton.Location = New-Object Drawing.Point(490, 585)
$closeButton.Size = New-Object Drawing.Size(110, 42)
$closeButton.Anchor = 'Bottom,Right'
$closeButton.Add_Click({ $form.Close() })
$form.Controls.Add($closeButton)

function Format-ArchesPlanText {
    param([Parameter(Mandatory)][object]$Plan)
    $lines = @(
        "Remediation: $($Plan.Id) - $($Plan.Title)",
        "Risk: $($Plan.Risk)",
        "Privileges: $($Plan.Privileges)",
        "Disruption: $($Plan.Disruption)",
        "Estimated duration: $($Plan.Duration)",
        "Protection tier: $($Plan.ProtectionTier)",
        "Reversible: $($Plan.Reversible)",
        "Ownership status: $($Plan.OwnershipStatus)",
        "Verification: $($Plan.Verification)",
        "Plan digest: $($Plan.Digest)",
        '',
        'Exact planned changes:'
    )
    if (-not @($Plan.Changes).Count) {
        $lines += '  No change is required.'
    }
    foreach ($change in @($Plan.Changes)) {
        $lines += "  $($change.TargetType) / $($change.Target) / $($change.Property): $($change.Before) -> $($change.After)"
    }
    if (-not $Plan.CanExecute) {
        $lines += ''
        $lines += "BLOCKED: $($Plan.BlockReason)"
    }
    $lines -join [Environment]::NewLine
}

$planButton.Add_Click({
    try {
        $selectedId = ([string]$fixPicker.SelectedItem).Split(' ')[0]
        $script:currentPlan = New-ArchesRemediationPlan -Id $selectedId `
            -ManagementOwnershipAttested:($selectedId -eq 'FIX-FW-001' -and $attestation.Checked)
        $planBox.Text = Format-ArchesPlanText -Plan $script:currentPlan
        $approval.Checked = $false
        $approval.Enabled = [bool]$script:currentPlan.CanExecute
        $runButton.Enabled = $false
    }
    catch {
        $script:currentPlan = $null
        $approval.Checked = $false
        $approval.Enabled = $false
        $runButton.Enabled = $false
        $planBox.Text = "Plan creation failed safely. No configuration changes were made.`r`n`r`n$($_.Exception.Message)"
    }
})

$approval.Add_CheckedChanged({
    $runButton.Enabled = $approval.Checked -and $null -ne $script:currentPlan -and $script:currentPlan.CanExecute
})

$fixPicker.Add_SelectedIndexChanged({
    $script:currentPlan = $null
    $approval.Checked = $false
    $approval.Enabled = $false
    $runButton.Enabled = $false
    $planBox.Text = 'Selection changed. Build a new read-only plan before approval.'
    $attestation.Enabled = ([string]$fixPicker.SelectedItem).StartsWith('FIX-FW-001')
})

$runButton.Add_Click({
    if ($null -eq $script:currentPlan -or -not $approval.Checked) { return }
    $answer = [Windows.Forms.MessageBox]::Show(
        'Run only the exact change shown in the current plan?',
        'Final approval',
        [Windows.Forms.MessageBoxButtons]::YesNo,
        [Windows.Forms.MessageBoxIcon]::Warning,
        [Windows.Forms.MessageBoxDefaultButton]::Button2
    )
    if ($answer -ne [Windows.Forms.DialogResult]::Yes) { return }
    try {
        $result = Invoke-ArchesRemediation -Plan $script:currentPlan `
            -RollbackDirectory $rollbackDirectory -Approved -Confirm:$false
        $message = "$($result.Message)"
        if ($result.RollbackPath) { $message += "`r`n`r`nRollback record: $($result.RollbackPath)" }
        [void][Windows.Forms.MessageBox]::Show($message, 'Change verified', 'OK', 'Information')
        $script:currentPlan = $null
        $approval.Checked = $false
        $approval.Enabled = $false
        $runButton.Enabled = $false
        $planBox.Text = 'The approved operation completed. Build a new plan to perform another change.'
    }
    catch {
        [void][Windows.Forms.MessageBox]::Show(
            "The change did not complete successfully.`r`n`r`n$($_.Exception.Message)",
            'Remediation stopped', 'OK', 'Error'
        )
    }
})

[void]$form.ShowDialog()
