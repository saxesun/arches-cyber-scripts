Set-StrictMode -Version 2.0

function Get-ArchesCategoryScore {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object[]]$Results, [Parameter(Mandatory)][string]$Category)
    $categoryResults = @($Results | Where-Object Category -eq $Category)
    $confirmedResults = @($categoryResults | Where-Object Status -in @('Pass', 'Warning', 'Fail'))
    $uncertainResults = @($categoryResults | Where-Object Status -in @('Unknown', 'Error'))
    if (-not $confirmedResults.Count) {
        return [PSCustomObject]@{
            Category = $Category
            Score = $null
            Rating = 'Not Scanned'
            CheckCount = $categoryResults.Count
            ConfirmedCheckCount = 0
            ProblemCount = 0
            UncertainCount = $uncertainResults.Count
        }
    }
    $penalties = @{ Critical=35; High=25; Medium=12; Low=5; Info=0 }
    $score = 100
    foreach ($result in $confirmedResults) {
        if ($result.Status -eq 'Fail') { $score -= $penalties[$result.Severity] }
        elseif ($result.Status -eq 'Warning') { $score -= [math]::Ceiling($penalties[$result.Severity] / 2) }
    }
    $score = [math]::Max(0, $score)
    $rating = if ($score -ge 90) { 'Great' } elseif ($score -ge 75) { 'Good' } elseif ($score -ge 50) { 'Not Good' } else { 'Bad' }
    [PSCustomObject]@{
        Category = $Category
        Score = $score
        Rating = $rating
        CheckCount = $categoryResults.Count
        ConfirmedCheckCount = $confirmedResults.Count
        ProblemCount = @($confirmedResults | Where-Object Status -ne Pass).Count
        UncertainCount = $uncertainResults.Count
    }
}

function Get-ArchesScorecard {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object[]]$Results)
    @('Security','Network','Hardware','Connected Devices','Performance') | ForEach-Object {
        Get-ArchesCategoryScore -Results $Results -Category $_
    }
}

Export-ModuleMember -Function Get-ArchesCategoryScore, Get-ArchesScorecard
