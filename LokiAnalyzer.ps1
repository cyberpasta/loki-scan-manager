<#
    .Title: Loki Scan Analyzer
    .Author: Ghassan Salem
    .Description:
        Parsed the output of loki scan in order to help analyzing the results and concentrate on the important.
    .Last Update: 30-JUN-2019

#>

#Get th Working Directory:
$WorkingDir= Split-Path -parent $PSCommandPath

#Input Folder
$ReportsFolder = "{0}\Reports" -f $WorkingDir
#Define Output Folder Location
$OutputPath = "{0}\Analyzed" -f $WorkingDir
# The Header Fields that will be parsed
$Header = "DateTime", "SERVER", "SEVERITY", "STAGE", "MESSAGE"

#Get All csv Files
$Files = Get-ChildItem -Path $ReportsFolder -Filter '*.csv'

$Results =@()

Foreach ($File in $Files )
{
 $Results += Import-Csv -Path $File.FullName -Header $Header | select *, @{Name='FileName';Expression={$File.BaseName}}
}

$Results = $Results | Select *, TYPE, REASON_1, ORIGINAL, MODIFIED, FILE, SIZE, CREATED, ACCESSED, SUBSCORE, SHA1, FIRST_BYTES, SHA256, MD5, SCORE, HOOKED, VERSION, SYSTEM , TIME, PLATFORM, PROC, BINARY, SOURCE, PID, Results, NAME, OWNER, CMD, PATH, COMMAND, IP, PORT, LIP, LPORT, RIP, RPORT, specified, ATTERN, ERROR, DESC, "73760" , "MATCH", "DESCRIPTION"
$headerz = "TYPE", "REASON_1", "ORIGINAL", "MODIFIED", "FILE", "SIZE", "CREATED", "ACCESSED", "SUBSCORE", "SHA1", "FIRST_BYTES", "SHA256", "MD5", "SCORE" ,"HOOKED", "VERSION", "SYSTEM", "TIME", "PLATFORM", "PROC", "BINARY", "SOURCE", "PID", "Results", "NAME", "OWNER", "CMD", "PATH", "COMMAND", "IP", "PORT", "LIP", "LPORT", "RIP", "RPORT", "specified", "PATTERN", "ERROR", "DESC", "73760","MATCH", "DESCRIPTION"


$tempString = $test
$pattern = "(?<Key>[a-zA-Z0-9_]+): (?<Value>(?:.*:\\)*[A-Za-z0-9!#$%&'*+.\\ =?^_`{|}~\/\(\)-]+(?:\d:\d)*[A-Za-z0-9!#$%&'*+.\\ =?^_`{|}~\/\(\)-]+) (?=[a-zA-Z0-9_]+: )|(?<Key2>[a-zA-Z0-9_]+): (?<Value2>(?:.*:)*[A-Za-z0-9!#$%&'*+.\\ =?^_`{|}~\/\(\)-]*(?:\d:\d)*[A-Za-z0-9!#$%&'*+.\\ =?^_`{|}~\/\(\)-]*)$"


$added = @()

$total=[int64]$Results.count
$i=0
Write-Host "total" $total


Foreach ($r in $Results)
{
    $tempString= $r.MESSAGE
    foreach ($match in [regex]::Matches($tempString, $pattern))
    {
        if ($match.Groups['Key'].Value)
        {
            if ($match.Groups['Key'].Value  -notin $headerz -and $match.Groups['Key'].Value -notin $added) {write-host $match.Groups['Key'].Value;$added +=$match.Groups['Key'].Value;}
            If ($match.Groups['Key'].Value -in $headerz) {$r[$match.Groups['Key'].Value] = $match.Groups['Value'].Value}
        }
        if ($match.Groups['Key2'].Value)
        {
            if ($match.Groups['Key2'].Value  -notin $headerz -and $match.Groups['Key2'].Value -notin $added ) {write-host $match.Groups['Key2'].Value;$added +=$match.Groups['Key2'].Value;}
            If ($match.Groups['Key2'].Value -in $headerz) {$r[$match.Groups['Key2'].Value] = $match.Groups['Value2'].Value}
        }
        
    }
    $i = $i + 1
    Write-Host  $i 
}

$added

#Export the Results
$Results | Out-GridView -PassThru | Export-csv -Path $("{0}\AnalyzedResults_{1}.csv" -f ($OutputPath,(Get-Date).ToString("yyyyMMdd_H_mm_s"))) -NoTypeInformation