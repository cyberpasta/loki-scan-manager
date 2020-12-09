           
                                                                                                                                                                         
LOKI IOC Scan Manager
=========================================================
Making LOKI IOC Scans Manageable Across Enterprise Windows Systems 

## History Behind:
Loki scanner is a well known and respected IOC scanner. Unfortunately it is a standalone tool that misses several options once we want to adopt it at the enterprise grade.

1. Loki scans only drive C: by default.
2. No capability to include or exclude a drive to the scan based on given conditions. e.g. We can't exclude scanning a drive if it is too large.
3. No easy way to track the status of the scans across all serves. e.g. can't easily identify what assets failed the scan. What asset is not reachable. 

## Solution:
LOKI IOC Scan Manager, is a powershell based script that comes into filling the missing gap between the power of powershell automation and the IOC scan capability of LOKI.

## Features:

- Centralized Management System for All scans
- Costomization, capability to select maximum concurrent scans
- capabilty to list the non system drives on the system and include them in the scan
- Capability to select the maximum used disk space
- LOKI Log Parser

## Structure:
The Automation script will have the following components under its folder:
-	**PowerPlaybook.ps1:** This is the core PowerShell script that holds the automation logic.
-	**Targets.txt:** this is a text file that contains the list of Machine Names to be scanned. The fully qualified domain name must be places one per line.
-	**PowerPlaybook.config:** This is the Configuration file that can control various settings such as max disk size, Max filesize to scan,  Enable/Disable  IP Resolution, Folder Detection, etc. 
-	**Reports Folder:** This folder will hold the reports gathered from each scanned machine. The reports are named as per the machine name. Make sure not to have the reports opened while running the scan the script will not be able to override the opened file. 
-	**Loki folder:** Holds the LOKI executables and signatures. This folder is being copied to each remote machine to be executed there.
-	**RunPowerPlaybook.bat:** This is a batch script that can be user to run PowerPlaybook.ps1 with all necessary keys and arguments.
-	**PowerPlaybook.ps1.sha256:** This is sha256 hash of the script “PowerPlaybook.ps1”. It is used to prove the integrity of the script as it was delivered.

## Method Of Operation:
-	The scrip will use the privilege of the user who initiated it
-	It Imports the list of assets subject for scanning from the file ” tragets.txt” and place them into a table 
-	For each machine from the list, perform a series of checks to make sure environment is ready for scan:
    - Check if server is pingable
    - Check if ports are open(445,135, DCOM)
    - Check if C$ is accessible
    - Check if Windows\Temp folder is accessible
    - Check if a process named Loki is already running on the system. The default setting is to kill the process and make sure it was properly killed
     - Check if an existing copy of Loki folder is already on the system
     - If a LOKI folder does exist on Windows/temp/loki, then the default action is to delete the folder
- The output of each of the above check is recorded in the same table of assets in preparation for exporting it later-on as a reference
- Now that we have identified what servers are good to go and which ones are not. Proceed with the list of servers that are ready for scanning
- For each server, copy LOKI folder from the source machine to the windows\temp folder on the remote server
- Wait for User approval. To initiate the scan press “Enter”
- The script starts executing the scripts in parallel according to the predefined value of maximum concurrent scans
- The scripts moves to the progress review menu, where you will see the list of currently running Scans
- Every time a scan finishes, the scrip will automatically push into the que a new machine from the list of scan ready targets
- Once all scans are done,
- Copy the Scan Report from the remote machine to the local scanning machine. Place the reports under the folder “Reports” 
- Delete the Remote LOKI Folder
- Display the Scan Summary Table in a grid View format
- Export the Scan report into the same folder of the script
- Wait for the user to press “Enter” to exit the scrip.

## Instructions to Run the Script:
### Preparation:

1.	Identify a machine to be used to initiate the scan:
  a.	It must be accessible to all servers to be scanned and able to connect to the following ports TCP ports 445, 135, 
  b.	Poweshell version of scanning machine needs to be minimum 4. Could be available on wondows10, windows server 2012 or 2016.
2.	Make sure that the servers to be scanned have WMI service enabled.
3.	Identify a domain account to be used for the scan.
4.	Assign to this Scanning User local admin privileges on all machines to be scanned.
5.	Open the file “targets.txt” and place the full list of servers you want to scan.
6.	Fine-tuning the Scan Settings: You can fine-tune your scan settings by editing the config file “PowerPlaybook.config”. These are the description of the config settings.
## Execution:
9. Now that we have a command prompt running with the privileges of the scanning user, Navigate to the folder where the Powershell script is located and execute the following command:
```python
powershell -ep bypass PowerPlaybook.ps1
```
OR
Just execute the following bat file and it will lunch the Powerplaybook:
```bash
RunPowerPlaybook.bat
```
10. For extra security, change the user password on every bunch of servers you scan.

## "PowerPlaybook.config" Settings:
| Key | Description |
|-----|-------------|
| &lt;add key="MaxJobsAtaTime" value="10"/&gt; | Number of simultaneous scans to be performed. Default is 10 |
| &lt;add key="ResolveHostIP" value="FALSE"/&gt; | Enable/Disable Resolve IP. Preferred to keep it FALSE |
| &lt;add key="DeletePayloadAfterEnd" value="TRUE"/&gt; | Preferred to keep it TRUE\. Set it False if you want to run multiple scans  on the same servers |
| &lt;add key="OverwritePayloadIfExists" value="TRUE"/&gt; | Preferred to be TRUE |
| &lt;add key="KillProcessIfAlreadyRunning" value="TRUE"/&gt; | Keep it TRUE |
| &lt;add key="ScanAllDrives" value="TRUE"/&gt; | Set FALSE to scan only C drive |
| &lt;add key="LimitDriveSize" value="TRUE"/&gt; | If set TRUE, then  MaxAllowableDriveSizeBytes will be applicable\.<br>If FALSE, will scan the drive regardless of its used space\. |
| &lt;add key="MaxAllowableDriveSizeBytes" value="1000000000000"/&gt; | Max allowed scanned used space in Bytes\. \(Not Disk Size\) | 
| &lt;add key="MaxErrorsPerExecution" value="1000"/&gt;  | How many errors are allowed to occur during execution stage. Needed to handle hosts that became problematic during the scan\. They will be timed-out\. |



## Reference:
[Neo23x0 Loki Repository](https://github.com/Neo23x0/Loki)
