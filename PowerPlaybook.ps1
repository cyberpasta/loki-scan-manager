#PowerPlaybookPLayer


#Author: Ghassan Salem
#Description: Batch Playbook execution.
#Date: 6-MAR-2019

# Features
# Gets a list of targets
# Ping
# IP Resolve
# Check if Payload Exist on Target
# Copy Payload to remote target
# Execute Payload on the remote system
# Copy report
# Delete Remote Palyoad
# Export Reports


##Improvement:
#Fix Pending Count
#Filter Excluded With Error
#Move and Delete Report inline
#Set Timeout per Scan
#Set Max File Size to smaller 0.5MB


#Get th Working Directory:
$WorkingDir= Split-Path -parent $PSCommandPath

##Ping Hosts if they are UP and Running:
Write-Host -ForeGroundColor Yellow "################"
Write-Host -ForeGroundColor Yellow "Loading Configuration Settings..."
Write-Host -ForeGroundColor Yellow "################"


##Loading Config Settings
$configFile = "{0}\PowerPlaybook.config" -f $WorkingDir
if(Test-Path $configFile) {
    Try {
        #Load config appsettings
        $global:appSettings = @{}
        $config = [xml](get-content $configFile)
        foreach ($addNode in $config.configuration.appsettings.add) {
            if ($addNode.Value.Contains(‘,’)) {
                # Array case
                $value = $addNode.Value.Split(‘,’)
                    for ($i = 0; $i -lt $value.length; $i++) { 
                        $value[$i] = $value[$i].Trim() 
                    }
            }
            else {
                # Scalar case
                $value = $addNode.Value
            }
        $global:appSettings[$addNode.Key] = $value
        }
    }
    Catch [system.exception]{
    Write-host "Error readingthe Configuration"
    exit(1)

    }
}

$MaxJobsAtaTime =[int]$appSettings["MaxJobsAtaTime"] #2
$ResolveHostIP= [System.Convert]::ToBoolean($appSettings["ResolveHostIP"])
$CheckOpenPorts= [System.Convert]::ToBoolean($appSettings["CheckOpenPorts"])
$CheckRemoteCShareAccesible= [System.Convert]::ToBoolean($appSettings["CheckRemoteCShareAccesible"])
$CheckRemoteWorkingDirectory= [System.Convert]::ToBoolean($appSettings["CheckRemoteWorkingDirectory"])
$DeletePayloadAfterEnd = [System.Convert]::ToBoolean($appSettings["DeletePayloadAfterEnd"])
$OverwritePayloadIfExists =[System.Convert]::ToBoolean($appSettings["OverwritePayloadIfExists"])
$KillProcessIfAlreadyRunning= [System.Convert]::ToBoolean($appSettings["KillProcessIfAlreadyRunning"])
$ScanAllDrives = [System.Convert]::ToBoolean($appSettings["ScanAllDrives"])
$LimitDriveSize = [System.Convert]::ToBoolean($appSettings["LimitDriveSize"]) 
$MaxAllowableDriveSizeBytes = [uint64]$appSettings["MaxAllowableDriveSizeBytes"]
$MaxErrorsPerExecution = [int]$appSettings["MaxErrorsPerExecution"]
$MaxFileSizeToScanKB = [int]$appSettings["MaxFileSizeToScanKB"]


write-host (" +MaxJobsAtaTime: {0}" -f $MaxJobsAtaTime)
write-host (" +ResolveHostIP: {0}" -f $ResolveHostIP)
write-host (" +DeletePayloadAfterEnd: {0}" -f $DeletePayloadAfterEnd)
write-host (" +OverwritePayloadIfExists: {0}" -f $OverwritePayloadIfExists)
Write-Host (" +KillProcessIfAlreadyRunning: {0}" -f $KillProcessIfAlreadyRunning)


#read-host "Press Enter to Proceed"
Start-Sleep 2

$Command= "{0}\loki\loki.exe --dontwait -s $MaxFileSizeToScanKB  --csv -l {0}\loki\{1}.csv"  #==> -f ($RemoteWorkingDir, $item.ComputerName)
$Command2= "{0}\loki\loki.exe --noprocscan --dontwait -s $MaxFileSizeToScanKB  --csv -l {0}\loki\{1}.csv -p {2}"  #==> -f ($RemoteWorkingDir, $item.ComputerName)

$TargetListFileName = $WorkingDir+"\targets.txt"
$TargetList = Get-Content $TargetListFileName

$RemoteWorkingDir = "C:\Windows\Temp"


$Drive = ($RemoteWorkingDir -split ":")[0]
$RemoteWorkingDirShare = ($RemoteWorkingDir -split ":")[1] -replace '\\','\\' 


#Functions Area:

function Get-Reports
{
    param ($item)
    Write-Host -ForeGroundColor Yellow "################"
    Write-Host -ForeGroundColor Yellow "Getting Reports From Targers..."
    Write-Host -ForeGroundColor Yellow "################"

    if (Test-Path $item.RemoteLogLocation -ErrorAction SilentlyContinue)
       {
       #then copy
       $DestPath = "{0}\Reports\" -f $WorkingDir
       $SourcePath = $item.RemoteLogLocation
       write-host -ForeGroundColor Green $("Getting Report: `n `t-Source: {0} `n `t-Destination:{1}" -f ($SourcePath, $DestPath))
       New-Item -Force -Path $DestPath -ItemType directory

       Copy-Item -Force -Recurse -Path $SourcePath -destination $DestPath

       }

}




Write-Host -ForeGroundColor Yellow "################"
Write-Host -ForeGroundColor Yellow "Environment Settings..."
Write-Host -ForeGroundColor Yellow "################"

Write-Host (" +Running as User: {0}" -f $env:USERNAME)
Write-host (" +Working Directory: {0}" -f $WorkingDir)

Start-Sleep 2



function GetIP ([String] $ComputerName)
{
Try
{
  Return $([System.Net.Dns]::GetHostAddresses($ComputerName) | where {$_.AddressFamily -notlike "InterNetworkV6"})[0]
 }
 Catch
 {
  Write-host $("Catched an error while resolving Traget: '{0}'" -f $ComputerName)
  Return ""
 }   
}


$GlobalArray =@()


foreach ($item in $TargetList)
{
 $GlobalArray += @{ComputerName = $item; IPAddress =""; PingSuccess="";PortOpen="";CAccessible ='';RmDirAccessible=""; LokiExists=""; wmiLokiExists="";wmiLokiExists2=""; Executed=""; ExecuteStatus=""; ExecuteStart=""; ExecuteEnd="";RunTime=""; ProcessID=""; PayloadDeleted = ""; ComandExecuted =""; DriveLetter =""; DriveName ="";UsedSpace=""  }
}


##Ping Hosts if they are UP and Running:
Write-Host -ForeGroundColor Yellow "################"
Write-Host -ForeGroundColor Yellow "Checking if Target is UP"
Write-Host -ForeGroundColor Yellow "################"

$PingProgress =0
foreach ($item in $GlobalArray)
{
$item.PingSuccess = Test-Connection $item.ComputerName -Count 1 -Quiet
$PingProgress+=1
    if ($item.PingSuccess)
    {
        write-Host -ForeGroundColor Green (" +Pinging {0}/{1}: {2}`tis UP" -f $PingProgress, $GlobalArray.Count,$item.ComputerName )
    }
    else
    {
        write-Host -ForeGroundColor Red (" +Pinging {0}/{1}: {2}`tis DOWN" -f $PingProgress, $GlobalArray.Count,$item.ComputerName )
    }

}


##Resolve to an IP Address:

Write-Host -ForeGroundColor Yellow "################"
Write-Host -ForeGroundColor Yellow "Resolve IP Address"
Write-Host -ForeGroundColor Yellow "################"

if($ResolveHostIP) {Write-host -ForeGroundColor Green "IP Resolve is Enabled!" } else {Write-host -ForeGroundColor Red "IP Resolve is Disabled!"}

if ($ResolveHostIP)
{

$ResolveIPProgress =0
foreach ($item in $GlobalArray)
{
    $item.IPAddress = GetIP($item.ComputerName)
    $ResolveIPProgress+=1
    write-Host (" +Resolving IPs {0}/{1}: {2}-->{3}" -f $ResolveIPProgress, $GlobalArray.Count,$item.ComputerName, $item.IPAddress)
}

}

##Check if Ports are open
Write-Host -ForeGroundColor Yellow "################"
Write-Host -ForeGroundColor Yellow "Check if Ports are Accessible"
Write-Host -ForeGroundColor Yellow "################"
if ($CheckOpenPorts)
{

    foreach ($item in $GlobalArray)
    {
    $OpenPorts=""
    $Global:ProgressPreference = 'SilentlyContinue' # this is to remove the progress bar of Test-NetConnection
    if (Test-NetConnection $item.ComputerName -Port 445 -InformationLevel Quiet) {$OpenPorts+="445,"; Write-host -ForeGroundColor Green $(" +Port {0}:445 OPEN" -f $item.ComputerName )} else {Write-host -ForeGroundColor Red $(" +Port {0}:445 CLOSED" -f $item.ComputerName )}
    if (Test-NetConnection $item.ComputerName -Port 135 -InformationLevel Quiet) {$OpenPorts+="135,"; Write-host -ForeGroundColor Green $(" +Port {0}:135 OPEN" -f $item.ComputerName )} else {Write-host -ForeGroundColor Red $(" +Port {0}:135 CLOSED" -f $item.ComputerName )}
    if (Test-NetConnection $item.ComputerName -Port 49153 -InformationLevel Quiet) {$OpenPorts+="49153"; Write-host -ForeGroundColor Green $(" +Port {0}:49153 OPEN" -f $item.ComputerName )} else {Write-host -ForeGroundColor Red $(" +Port {0}:49153 CLOSED" -f $item.ComputerName )}
    $item.PortOpen = $OpenPorts
    }
}else
{
    Write-Host -ForeGroundColor Red " +Check OpenPorts Disabled: Disabled"
}


##Check C$
Write-Host -ForeGroundColor Yellow "################"
Write-Host -ForeGroundColor Yellow "Check if C$ is Accessible"
Write-Host -ForeGroundColor Yellow "################"

if ($CheckRemoteCShareAccesible)
{
    foreach ($item in $GlobalArray)
    {
        $item.CAccessible= Test-Path "\\$($item.ComputerName)\c$" -ErrorAction SilentlyContinue
        if ($item.CAccessible) {Write-Host -ForegroundColor Green $(" +\\$($item.ComputerName)\c$ Is Accessible")} 
        else {Write-Host -ForegroundColor Red $(" +\\$($item.ComputerName)\c$ Not Accessible")}
    }
}
Else
{
    Write-Host -ForeGroundColor Red " +Check Remote C Share Accessible: Disabled"
}

##Check if working Directory is accessible
Write-Host -ForeGroundColor Yellow "################"
Write-Host -ForeGroundColor Yellow "Check if Remote Working Directory is Accessible"
Write-Host -ForeGroundColor Yellow "################"
if ($CheckRemoteWorkingDirectory)
{
    foreach ($item in $GlobalArray)
    {
        $TemPath = "\\{0}\{1}`${2}" -f $item.ComputerName, $Drive, ($RemoteWorkingDir -split ":")[1]
        $item.RmDirAccessible= Test-Path $TemPath -ErrorAction SilentlyContinue
        if ($item.RmDirAccessible) {Write-Host -ForegroundColor Green $(" +$TemPath Is Accessible")} 
        else {Write-Host -ForegroundColor Red $(" +$TemPath Not Accessible")}
    }
}
Else
{
    Write-Host -ForeGroundColor Red " +Check Remote Working Directory:Disabled"
}



if ($KillProcessIfAlreadyRunning)
{
    ##Get Processes and kill using CIM
    Write-Host -ForeGroundColor Yellow "################"
    Write-Host -ForeGroundColor Yellow "Kill Any Loki Process Already Running!"
    Write-Host -ForeGroundColor Yellow "################"
    foreach ($item in $GlobalArray | ?{$_.CAccessible})
    {
        #Write-Host -ForeGroundColor Gray $(" +Kill ") 
        Get-cimInstance -Class Win32_Process -computername $item.ComputerName -Filter "Name = 'loki.exe'" -ErrorAction SilentlyContinue | Invoke-CimMethod -MethodName Terminate -ErrorAction SilentlyContinue
    }
}

##Check if Loki file Exists using WMI
Write-Host -ForeGroundColor Yellow "################"
Write-Host -ForeGroundColor Yellow "Checking if Payload Exists on Target"
Write-Host -ForeGroundColor Yellow "################"

foreach ($item in $GlobalArray)
{

    $testpath =  $RemoteWorkingDirShare + "\\LOKI\\"

     
    try {
    $filterstr = "Drive='C:' AND Path='{0}' AND FileName='loki' AND Extension ='exe'" -f $testpath
    $result = Get-WMIObject -Class CIM_DataFile -Filter $filterstr -computername $item.ComputerName -ErrorAction SilentlyContinue |Format-List *
    }
    catch {
    $result = $null
    }
    if ($null -ne $result -and $result.count -gt 0)
    {
        Write-Host -ForeGroundColor Green " +Path Exists on $($item.ComputerName)"; $item.wmiLokiExists = "True" 
    }
    Else
    {
        Write-Host -ForeGroundColor Red " +Path Does Not Exists on $($item.ComputerName)"; $item.wmiLokiExists = "False"
    }
}

##File Share Copy
Write-Host -ForeGroundColor Yellow "################"
Write-Host -ForeGroundColor Yellow "Moving Files to Target"
Write-Host -ForeGroundColor Yellow "################"

foreach ($item in $GlobalArray)
{
if ( -not ($OverwritePayloadIfExists -eq $false -and $item.wmiLokiExists -eq "True") -and $item.PingSuccess -eq $true -and ( Test-Path "\\$($item.ComputerName)\c$" -ErrorAction SilentlyContinue))
   {
   #then copy
   #$RemoteWorkingDir
   $sharep = $RemoteWorkingDir -replace ':','$'
   $DestPath =  "\\{0}\{1}" -f $item.ComputerName,$sharep
   $SourcePath = "{0}\loki" -f $WorkingDir
   write-host -ForeGroundColor Green $(" +Copying source: {0} to Destination:{1}" -f ($SourcePath, $DestPath))
   New-Item -Force -Path $DestPath -ItemType directory

   Copy-Item -Force -Recurse -Path $SourcePath -destination $DestPath # -ErrorAction SilentlyContinue

   }

}


##Check if Loki file Exists using WMI
Write-Host -ForeGroundColor Yellow "################"
Write-Host -ForeGroundColor Yellow "Checking if Payload Exists on Target"
Write-Host -ForeGroundColor Yellow "################"

foreach ($item in $GlobalArray)
{

    $testpath =  $RemoteWorkingDirShare + "\\LOKI\\"

     
    try {
    $filterstr = "Drive='C:' AND Path='{0}' AND FileName='loki' AND Extension ='exe'" -f $testpath
    $result = Get-WMIObject -Class CIM_DataFile -Filter $filterstr -computername $item.ComputerName -ErrorAction SilentlyContinue |Format-List *
    }
    catch {
    $result = $null
    }
    if ($null -ne $result -and $result.count -gt 0)
    {
        Write-Host -ForeGroundColor Green " +Path Exists on $($item.ComputerName)"; $item.wmiLokiExists2 = "True" 
    }
    Else
    {
        Write-Host -ForeGroundColor Red " +Path Does Not Exists on $($item.ComputerName)"; $item.wmiLokiExists2 = "False"
    }
}




# ComandExecuted =""; DriveLetter =""


Write-Host -ForeGroundColor Yellow "################"
Write-Host -ForeGroundColor Yellow "Inseting Commands into the pipe"
Write-Host -ForeGroundColor Yellow "################"


$JobQueuedt = New-Object System.Data.Datatable
$JobQueuedt.TableName ="JobQueue"
[void]$JobQueuedt.Columns.Add("ComputerName")
[void]$JobQueuedt.Columns.Add("IPAddress")
[void]$JobQueuedt.Columns.Add("PingSuccess")
[void]$JobQueuedt.Columns.Add("PortOpen")
[void]$JobQueuedt.Columns.Add("CAccessible")
[void]$JobQueuedt.Columns.Add("RmDirAccessible")
[void]$JobQueuedt.Columns.Add("LokiExists")
[void]$JobQueuedt.Columns.Add("wmiLokiExists")
[void]$JobQueuedt.Columns.Add("wmiLokiExists2")
[void]$JobQueuedt.Columns.Add("Executed")
[void]$JobQueuedt.Columns.Add("ExecuteStatus")
[void]$JobQueuedt.Columns.Add("ExecuteStart")
[void]$JobQueuedt.Columns.Add("ExecuteEnd")
[void]$JobQueuedt.Columns.Add("RunTime")
[void]$JobQueuedt.Columns.Add("ProcessID")
[void]$JobQueuedt.Columns.Add("PayloadDeleted")
[void]$JobQueuedt.Columns.Add("ComandExecuted")
[void]$JobQueuedt.Columns.Add("DriveLetter")
[void]$JobQueuedt.Columns.Add("DriveName")
[void]$JobQueuedt.Columns.Add("UsedSpace")
[void]$JobQueuedt.Columns.Add("RemoteLogLocation")
[void]$JobQueuedt.Columns.Add("ErrorCount")
[void]$JobQueuedt.Columns.Add("ErrorMessage")
$JobQueuedt.Columns["ErrorCount"].DefaultValue = 0 #Had to add it as I was receiving error comparing with DBnull value

foreach ($item in $GlobalArray)
{   
    Write-host "wmiloki2 " $item.wmiLokiExists2 $item.ComputerName
    if ($item.wmiLokiExists2) #If Machine is accessible
    {
        $result = $null
        try
        {
            $result= GET-WMIOBJECT -Class win32_logicaldisk -ComputerName $item.ComputerName -Filter "DriveType='3' AND Size > 0" -ErrorAction Stop
            #if the return value was a single item, then it wil not be returned as an array. Thus, I need to cast the returned value to an array to deal with it in a unified way.
            if ($result -isnot [system.array])
            {
                $result = @($result)
                #Write-Host -ForeGroundColor Green "Casting to Array"
            }
            
            Write-Host -ForeGroundColor Green "List of Drives:" $result.count
            $result
            #Sample Output:
            #DeviceID     : C:
            #DriveType    : 3
            #ProviderName : 
            #FreeSpace    : 9229000704
            #Size         : 31657553920
            #VolumeName   :

        }
        Catch
        {
            $result= $null
            Write-Host -ForeGroundColor Red "Error Getting the Drives"
        }
        if ($result -ne $null -and $result.count -gt 0)
        {
            foreach ($driveLetter in $result)
            {
                if (($True,$($driveLetter.Size - $driveLetter.FreeSpace) -le $MaxAllowableDriveSizeBytes )[$LimitDriveSize] )
                {
                    if ($driveLetter.DeviceID -eq 'C:')
                        {
                            $LOKICommand = $Command -f ($RemoteWorkingDir, $($item.ComputerName+"_"+ $driveLetter.DeviceID -replace ":",""))
                            #$r= $JobQueuedt.Rows.Add($($item.Values))
                            $r = $JobQueuedt.Rows.Add()
                            $item.Keys | ForEach-Object { $r[$_]= $item[$_] }
                            $r["ComandExecuted"] = $LOKICommand
                            $r["DriveLetter"] = $driveLetter.DeviceID + "\"
                            $r["DriveName"]= $driveLetter.VolumeName
                            $($driveLetter.Size - $driveLetter.FreeSpace) | ForEach-Object {$r["UsedSpace"] = $([math]::Round($_ /[Math]::Pow(1024,3),2)).ToString() + "GB = " + $([math]::Round($_ /[Math]::Pow(1024,2),2)).ToString() + "MB"}
                            $RemoteFileLocation = "\\{0}\{1}\loki\{2}_{3}.csv" -f ($item.ComputerName, $($RemoteWorkingDir -replace ':','$'),$item.ComputerName,$($driveLetter.DeviceID -replace ":","") )
                            $r["RemoteLogLocation"] = $RemoteFileLocation
                        }
                        elseif ($driveLetter.DeviceID -ne "")
                        {
                            if ($ScanAllDrives)
                            {
                                $LOKICommand = $Command2 -f ($RemoteWorkingDir, $($item.ComputerName+"_"+ $driveLetter.DeviceID -replace ":","") ,$($driveLetter.DeviceID + "\"))
                                $r= $JobQueuedt.Rows.Add()
                                $item.Keys | ForEach-Object { $r[$_]= $item[$_] }
                                $r["ComandExecuted"] = $LOKICommand
                                $r["DriveLetter"] = $driveLetter.DeviceID + "\"
                                $r["DriveName"]= $driveLetter.VolumeName
                                $($driveLetter.Size - $driveLetter.FreeSpace) | ForEach-Object {$r["UsedSpace"] = $([math]::Round($_ /[Math]::Pow(1024,3),2)).ToString() + "GB = " + $([math]::Round($_ /[Math]::Pow(1024,2),2)).ToString() + "MB"}
                                #$r["UsedSpace"] = ($driveLetter.Size - $driveLetter.FreeSpace)/(1024*1024)
                                $RemoteFileLocation = "\\{0}\{1}\loki\{2}_{3}.csv" -f ($item.ComputerName, $($RemoteWorkingDir -replace ':','$'),$item.ComputerName,$($driveLetter.DeviceID -replace ":","") )
                                $r["RemoteLogLocation"] = $RemoteFileLocation
                            }else #All Drives Is Disabled
                            {
                                $r= $JobQueuedt.Rows.Add()
                                $item.Keys | ForEach-Object { $r[$_]= $item[$_] }
                                $r["ExecuteStatus"] = "Excluded: Multi Drive Scan is Disabled"
                                $r["Executed"] = "No"
                                $r["DriveLetter"] = $driveLetter.DeviceID + "\"
                                $r["DriveName"]= $driveLetter.VolumeName
                                $($driveLetter.Size - $driveLetter.FreeSpace) | ForEach-Object {$r["UsedSpace"] = $([math]::Round($_ /[Math]::Pow(1024,3),2)).ToString() + "GB = " + $([math]::Round($_ /[Math]::Pow(1024,2),2)).ToString() + "MB"}
                                #$r["UsedSpace"] = ($driveLetter.Size - $driveLetter.FreeSpace)/(1024*1024)

                            }

                        }
                }else
                {
                    $r= $JobQueuedt.Rows.Add()
                    $item.Keys | ForEach-Object { $r[$_]= $item[$_] }
                    $r["ExecuteStatus"] = "Excluded: Drive Used Space Exceeds Maximum Allowed Space"
                    $r["Executed"] = "No"
                    $r["DriveLetter"] = $driveLetter.DeviceID + "\"
                    $r["DriveName"]= $driveLetter.VolumeName
                    $($driveLetter.Size - $driveLetter.FreeSpace) | ForEach-Object {$r["UsedSpace"] = $([math]::Round($_ /[Math]::Pow(1024,3),2)).ToString() + "GB = " + $([math]::Round($_ /[Math]::Pow(1024,2),2)).ToString() + "MB"}
                }
            } 

        }
        else
        {
            #Could not Get The Drives, Add a row with error and move to the next computer.
            
            $r= $JobQueuedt.Rows.Add()
            $item.Keys | ForEach-Object { $r[$_]= $item[$_] }
            $r["ExecuteStatus"] = "Error: Unable to Get Drives"
            $r["Executed"] = "No"    
        }
            
     }else #If Machine was not accessible 
     {      
        $item.ExecuteStatus="Excluded"
        $item.Executed = "No"
        $r= $JobQueuedt.Rows.Add()
        $item.Keys | ForEach-Object { $r[$_]= $item[$_] }
        $r["ExecuteStatus"] = "Error: Loki Folder Inaccessible"
        $r["Executed"] = "No"
     }
    
}

$JobQueuedt | Format-Table


read-host "Proceed to Execute?"


Write-Host -ForeGroundColor Yellow "################"
Write-Host -ForeGroundColor Yellow "Execute Commands"
Write-Host -ForeGroundColor Yellow "################"


#Loki Command:
$maxConcurrentJobs = $MaxJobsAtaTime
$RunningCount =0

#Get list of jobs still not ececuted yet
$ActiveQueueList = $JobQueuedt.Where({$_.Executed -ne "No" -and $_.wmiLokiExists2 -eq $True})
$Remainingct = $ActiveQueueList.count

#Get the list of Jobs currently Running
$Running = $JobQueuedt.Where({$_.Executed -eq "Yes" -and $_.ExecuteStatus -eq "Running" -and $_.wmiLokiExists2 -eq $True})

#This is to calculate time ellapsed
$initialTime =(Get-Date)
while ($Remainingct -gt 0)
{
    #For each Candidates ("" or "Running")
    #Check if exceeded maxQueSize
        #if exceeded: loop + delay
        #if Still Room:
            # if status "" and does not have same computer but running
                #then add it to the queue
        #if Status is running ==> Check if it is still running and update.
        #delay
        #update
        #write-host "Running Count" $Running.Count
        if ($Running.Count -lt $maxConcurrentJobs)
        {
            $Candidates = $JobQueuedt.Where({$_.Executed -eq "" -and $_.Executed -ne "No"  -and $_.ComandExecuted -ne "" -and $_.wmiLokiExists2 -eq $True})
            foreach ($Candidate in $Candidates)
            {
                #check if there are other processes currently running on the same machine.
                if ($JobQueuedt.Where({$_.ComputerName -eq $Candidate.ComputerName -and $_.Executed -eq "Yes" -and $_.ExecuteStatus -eq "Running" -and $_.wmiLokiExists2 -eq $True}).count -eq 0)
                {
                    #add a job to the Queue & Update the Queue
                    $Candidate.Executed = "Yes"
                    $newproc = Invoke-WmiMethod -class Win32_process -name Create -ArgumentList ($Candidate.ComandExecuted) -ComputerName $Candidate.ComputerName -ErrorAction SilentlyContinue
                    #write-host $newproc.ReturnValue
                    #Write-host $newproc.ProcessId
                   

                    if ($newproc.ReturnValue -eq 0) #if process run successfully return =0
                    {
                        Write-Host -ForeGroundColor Green " +Adding One Machine to Queue: $($item.ComputerName)"
                        $Candidate.ExecuteStatus= "Running"
                        $Candidate.ProcessID = $newproc.ProcessId
                        $Candidate.ExecuteStart = Get-Date                   
                    }
                    else
                    {
                        Write-host -ForeGroundColor Red "Error Execution on Target: $($item.ComputerName)"
                        $Candidate.ExecuteStatus= "Error: Failed to Execute"
                        #Executed=""; ExecuteStatus=""; ExecuteStart=""; ExecuteEnd=""
                    }
                    break # break the foreach look to allow start again from the top of the list.
    
                }              
               
            }
            
        }
        Start-Sleep -m 1000
        $Running = $JobQueuedt.Where({$_.Executed -eq "Yes" -and $_.ExecuteStatus -eq "Running" -and $_.wmiLokiExists2 -eq $True})
        foreach ($runn in $Running)
        {

            try
            {
                $runningCheck = Get-WmiObject -Class Win32_Process -Filter "name='loki.exe'" -ComputerName $runn.ComputerName -ErrorAction Stop #Set to Stop to raise an exception on error
                #Write-Host "output of proc check: " $runningCheck
                if ($null -eq  $runningCheck)
                {
                #   write-host ("Inside if for proccessID {0} on {1}..." -f ($running.ProcessId, $running.ComputerName) )
                    $runn.ExecuteStatus = "Success"
                    $runn.ExecuteEnd = (Get-Date)

                    #Get The Report
                    Get-Reports $runn                                         
                }
            }
            catch [System.Exception]
            {
                $runn.ErrorCount = $([int]$runn.ErrorCount) +1
                $runn.ErrorMessage = $_.Exception.Message
            }
            if ([int]$runn.ErrorCount -ge $MaxErrorsPerExecution)
            {
                $runn.ExecuteStatus = "Aborted: Max Error Exceeded"
                $runn.ExecuteEnd = (Get-Date)
                
                 #Get The Report
                 Get-Reports $runn                
            }

            $TimeSpan = NEW-TIMESPAN –Start $runn.ExecuteStart -End (Get-Date) #((Get-Date) - $runn.ExecuteStart)
            $Duration = $TimeSpan.Days.ToString()+"d:"+$TimeSpan.Hours.ToString() +"h:"+$TimeSpan.Minutes.ToString()+"m:"+$TimeSpan.Seconds.ToString()+"s"
            $runn.RunTime= $Duration
            

        }
        $Running = $JobQueuedt.Where({$_.Executed -eq "Yes" -and $_.ExecuteStatus -eq "Running" -and $_.wmiLokiExists2 -eq $True})
        #should loop until all pending and all running jobs are done.

        $StillPendingCount = $JobQueuedt.Where({$_.Executed -eq "" -and $_.ExecuteStatus -eq "" -and $_.wmiLokiExists2 -eq $True}).count
        $Remainingct = $StillPendingCount +$running.count
        
        #read-host "Go Another Loop?"

        #Display Progress:
        Clear Screen 
        Get-Variable true | Out-Default; Clear-Host;
        
         

        $ellapsedtime = NEW-TIMESPAN –Start $initialTime -End (Get-Date)
        $ellapsedtime_text = $ellapsedtime.Days.ToString()+"d:"+$ellapsedtime.Hours.ToString() +"h:"+$ellapsedtime.Minutes.ToString()+"m:"+$ellapsedtime.Seconds.ToString()+"s"
        write-host -ForeGroundColor Green "Progress[Currently Running:" $Running.count "][Still Pending:" $StillPendingCount "][Total Ellapsed Time: " $ellapsedtime_text "]"
        Write-Host -ForeGroundColor Yellow "#### Jobs Currently Running:"
        $JobQueuedt.Where({$_.Executed -eq "Yes" -and $_.ExecuteStatus -eq "running"}) | Select-Object -Property ComputerName,PingSuccess,wmiLokiExists2,Executed,ExecuteStatus,ExecuteStart,ExecuteEnd, RunTime, DriveLetter, UsedSpace | Format-Table
        Write-Host -ForeGroundColor Yellow "#### Jobs Pending to Run:"
        $JobQueuedt.Where({$_.Executed -eq "" -and $_.ExecuteStatus -eq ""}) | Select-Object -Property ComputerName,PingSuccess,wmiLokiExists2,Executed,ExecuteStatus,ExecuteStart,ExecuteEnd, RunTime, DriveLetter, UsedSpace | Format-Table
        Write-Host -ForeGroundColor Yellow "#### Jobs Done:"
        $JobQueuedt.Where({$_.Executed -eq "Yes" -and $_.ExecuteStatus -ne "" -and $_.ExecuteStatus -ne "running"  }) | Select-Object -Property ComputerName,PingSuccess,wmiLokiExists2,Executed,ExecuteStatus,ExecuteStart,ExecuteEnd, RunTime, DriveLetter, UsedSpace | Format-Table
        Write-Host -ForeGroundColor Yellow "#### Jobs Not Executed:"
        $JobQueuedt.Where({$_.Executed -eq "No"}) | Select-Object -Property ComputerName,PingSuccess,wmiLokiExists2,Executed,ExecuteStatus,ExecuteStart,ExecuteEnd, RunTime, DriveLetter, UsedSpace | Format-Table
            
         
}

Write-host "Got out of the loop"

#Once Scan is confirmed as done, delete the remote payload.
if ($DeletePayloadAfterEnd)
{

    Write-Host -ForeGroundColor Yellow "################"
    Write-Host -ForeGroundColor Yellow "Delete Payload From Remote Host..."
    Write-Host -ForeGroundColor Yellow "################"

    Write-Host "Sleeping for 5 Seconds, to keep space for process to end"
    Start-sleep 5

    $WithLoki = $JobQueuedt.Where({$_.wmiLokiExists2 -eq $True -and $_.DriveLetter -eq "C:\" })
    foreach ($item in $WithLoki)
       {
            $LOKICommand ="cmd.exe /C rmdir {0}\loki /s /q" -f ($RemoteWorkingDir)
            $newproc = Invoke-WmiMethod -class Win32_process -name Create -ArgumentList ($LOKICommand) -ComputerName $item.ComputerName -ErrorAction SilentlyContinue
               
            if ($newproc.ReturnValue -eq 0 ) 
            {
                write-host -ForeGroundColor Green (" +Directory Deleted on {0}" -f $item.ComputerName )
                $item.PayloadDeleted = "YES"
            }                       
       }
}
$JobQueuedt |Select-Object -Property ComputerName,IPAddress,PingSuccess,LokiExists,wmiLokiExists2,Executed,ExecuteStatus,ExecuteStart,ExecuteEnd, RunTime, PayloadDeleted, DriveLetter, UsedSpace,DriveName, ComandExecuted, RemoteLogLocation  | Out-GridView

## Exporting the The Results Table
Write-Host -ForeGroundColor Yellow "################"
Write-Host -ForeGroundColor Yellow "Exporting the The Results Table"
Write-Host -ForeGroundColor Yellow "################"
$OUTFILE = "{0}\RUNHISTORY_{1}.csv" -f ($WorkingDir,(Get-Date).ToString("yyyyMMdd_H_mm_s"))
$JobQueuedt | Select-Object -Property ComputerName,IPAddress,PingSuccess,LokiExists,wmiLokiExists,wmiLokiExists2,Executed,ExecuteStatus,ExecuteStart,ExecuteEnd, RunTime, PayloadDeleted, UsedSpace,DriveName, DriveLetter, ComandExecuted, RemoteLogLocation |export-csv $OUTFILE -NoTypeInformation

write-host "Done"

read-host "Press Enter to Exit.."
