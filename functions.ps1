Function New-TempFileName {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $false)]
		[string]
		$Extension = ".tmp"
	)
	$Guid = (New-Guid).Guid
	$FileName = $Guid + $Extension
	return $FileName
}

function Get-File {
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true,
			Position = 0)]
		[object]$File,

		[Parameter(Mandatory = $true,
			Position = 1)]
		[string]$Destination,

		[Parameter(Mandatory = $true,
			Position = 2)]
		[object]$Session,

		[Parameter(Position = 3)]
		[object]$TransferOptions,

		[Parameter()]
		[switch]
		$DeleteFile
	)
	$Transfer = $Session.GetFiles($File, $Destination, $DeleteFile, $TransferOptions)

	$Transfer.Check()
	return $Transfer
}

function Push-File {
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true,
			Position = 0)]
		[object]$File,

		[Parameter(Mandatory = $true,
			Position = 0)]
		[string]$Destination,

		[Parameter(Mandatory = $true,
			Position = 2)]
		[object]$Session,

		[Parameter(Position = 3)]
		[object]$TransferOptions,

		[Parameter()]
		[switch]
		$DeleteFile
	)
	$Transfer = $Session.PutFiles($File, $Destination, $DeleteFile, $TransferOptions)

	$Transfer.Check()
	return $Transfer
}

function New-MFGetFileTransferScript {
	[CmdletBinding()]
	param (
		[Parameter()]
		[pscredential]
		$Credential = (Get-Credential),

		[Parameter()]
		[String]
		$ComputerName,

		[Parameter()]
		[String]
		$FtpDirectory,

		[Parameter()]
		[String]
		$FtpFile,

		[Parameter()]
		[String]
		$DestinationFullName,

		[Parameter()]
		[String]
		$ScriptOutputFullName,

		[Parameter()]
		[switch]
		$DeleteFile
	)

	$UserName = $Credential.UserName
	$Password = $Credential.GetNetworkCredential().Password
	$CertificateFingerprint = Get-FtpsFingerprint -ComputerName $ComputerName
	if ($DeleteFile) { $delete = "-delete" }
	else { $delete = "" }
	$Script = @"
option batch on
option confirm off
open ftp://$($UserName):$($Password)@$($ComputerName):21 -explicittls -certificate="$CertificateFingerprint"
ASCII
cd /
cd $FtpDirectory
get $delete "$FtpFile" "$DestinationFullName"
bye
"@

	Out-File -LiteralPath $ScriptOutputFullName -Force -InputObject $Script | Out-Null
}
function New-MFPutFileTransferScript {
	[CmdletBinding()]
	param (
		[Parameter()]
		[pscredential]
		$Credential = (Get-Credential),

		[Parameter()]
		[String]
		$ComputerName,

		[Parameter()]
		[String]
		$FtpDirectory,

		[Parameter()]
		[String]
		$FtpFile,

		[Parameter()]
		[String]
		$SourceFullName,

		[Parameter()]
		[String]
		$ScriptOutputFullName,

		[Parameter()]
		[switch]
		$DeleteFile
	)

	$UserName = $Credential.UserName
	$Password = $Credential.GetNetworkCredential().Password
	$CertificateFingerprint = Get-FtpsFingerprint -ComputerName $ComputerName
	if ($DeleteFile) { $delete = "-delete" }
	else { $delete = "" }
	$Script = @"
option batch on
option confirm off
open ftp://$($UserName):$($Password)@$($ComputerName):21 -explicittls -certificate="$CertificateFingerprint"
ASCII
cd /
cd $FtpDirectory
put $delete "$SourceFullName" "$FtpFile"
bye
"@

	Out-File -LiteralPath $ScriptOutputFullName -Force -InputObject $Script | Out-Null
}
function Invoke-MFFtpTransferScript {
	[CmdletBinding()]
	param (
		[Parameter()]
		[string]
		$WinSCPComFile,

		[Parameter()]
		[string]
		$FtpSessionLogDirectory,

		[Parameter()]
		[string]
		$ScriptFile,

		[Parameter()]
		[string]
		$ComputerName
	)
	$ScriptFile = (Get-Item $ScriptFile).FullName
	$RedirectOutputFile = $ScriptFile + '.log'
	$WinSCPComFile = (Get-Item $WinSCPComFile).FullName
	$FtpSessionLogDirectory = (Get-Item $FtpSessionLogDirectory).FullName
	$SessionLog = Join-Path $FtpSessionLogDirectory "$(Get-Date -Format FileDate).$ComputerName.Session.log"
	$Process = Start-Process -FilePath "$WinSCPComFile" -ArgumentList "/script=`"$ScriptFile`" /ini=nul /log=`"$SessionLog`"" -Wait -PassThru -NoNewWindow -RedirectStandardOutput $RedirectOutputFile

	If ($Process.ExitCode -eq 0) { return }
	else {
		$LogFile = Get-Content $RedirectOutputFile
		if ($LogFile -match "Access denied.") {
			Throw "Failed to connect to server '$ComputerName'. Invalid username/password."
		}
		elseif ($LogFile -match "Could not retrieve file information") {
			Throw "File does not exist."
		}
		elseif ($LogFile -match "Connection failed.") {
			Throw "Failed to connect to server '$ComputerName'. Server unavailable."
		}
		elseif ($LogFile -match "Peer certificate rejected") {
			Throw "Failed to connect to server '$ComputerName'. Certificate fingerprint does not match."
		}
		else {
			Throw "Unknown error transferring file from server '$ComputerName'."
		}
	}
}

function Remove-MFFtpTransferScript {
	[CmdletBinding()]
	param (
		[Parameter()]
		[string]
		$ScriptFile
	)
	if (Test-Path -LiteralPath $ScriptFile -PathType Leaf) {
		Remove-Item -LiteralPath $ScriptFile -Force -Confirm:$False -ErrorAction SilentlyContinue | Out-Null
	}
	$RedirectOutputFile = $ScriptFile + '.log'
	if (Test-Path -LiteralPath $RedirectOutputFile -PathType Leaf) {
		Remove-Item -LiteralPath $RedirectOutputFile -Force -Confirm:$False -ErrorAction SilentlyContinue | Out-Null
	}
}

function Get-AzureBlobFile {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[string]
		$StorageAccountName,

		[Parameter(Mandatory = $true)]
		[string]
		$StorageAccountKey,

		[Parameter(Mandatory = $true)]
		[string]
		$Container,

		[Parameter(Mandatory = $true)]
		[string]
		$SourceFileName,

		[Parameter(Mandatory = $true)]
		[string]
		$DestinationFileFullPath,

		[Parameter()]
		[switch]
		$DeleteFile
	)

	$Context = New-AzStorageContext -StorageAccountName $StorageAccountName -StorageAccountKey $StorageAccountKey

	$Results = Get-AzStorageBlobContent -Context $Context -Container $Container -Blob $SourceFileName -Destination $DestinationFileFullPath -Confirm:$false -Force

	if ($DeleteFile) {
		Remove-AzStorageBlob -Context $Context -Container $Container -Blob $SourceFileName -Confirm:$false -Force
	}

	return $Results
}
function Push-AzureBlobFile {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[string]
		$StorageAccountName,

		[Parameter(Mandatory = $true)]
		[string]
		$StorageAccountKey,

		[Parameter(Mandatory = $true)]
		[string]
		$Container,

		[Parameter(Mandatory = $true)]
		[string]
		$SourceFileFullPath,

		[Parameter(Mandatory = $true)]
		[string]
		$DestinationFileName,

		[Parameter()]
		[switch]
		$DeleteFile
	)

	$Context = New-AzStorageContext -StorageAccountName $StorageAccountName -StorageAccountKey $StorageAccountKey

	$Results = Set-AzStorageBlobContent -Context $Context -Container $Container -File $SourceFileFullPath -Blob $DestinationFileName -Confirm:$false -Force

	if ($DeleteFile) {
		Remove-Item -LiteralPath $SourceFileFullPath -Confirm:$false -Force | Out-Null
	}

	return $Results
}
function New-TransferOptions {
	[CmdletBinding()]
	param
	(
		[bool]
		$PreserveTimestamp = $true,

		[ValidatePattern('[0-7]{3,4}')]
		[string]
		$FilePermissions = $null,

		[ValidateSet('Binary', 'Ascii', 'Automatic')]
		[string]
		$TransferMode = 'Binary',

		[string]
		$FileMask = $null,

		[ValidateSet('Default', 'On', 'Off', 'Smart')]
		[string]
		$ResumeSupport = 'Default',

		[int32]
		$SpeedLimit = 0,

		[ValidateSet('Overwrite', 'Resume', 'Append')]
		[string]
		$OverwriteMode = 'Overwrite'
	)

	$transferOptions = New-Object WinSCP.TransferOptions
	if ($FilePermissions) {
		$PSBoundParameters.FilePermissions = New-Object WinSCP.FilePermissions -Property @{ Octal = $FilePermissions }
	}
	if ('ResumeSupport' -in $PSBoundParameters.Keys) {
		$PSBoundParameters.ResumeSupport = New-Object WinSCP.TransferResumeSupport -Property @{State = $ResumeSupport }
	}
	$PSBoundParameters.GetEnumerator() | ForEach-Object {
		$transferOptions."$($_.Key)" = $_.Value
	}
	return $transferOptions
}

function Get-LocalFileHash {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $True)]
		[string]
		$Path,

		[Parameter(Mandatory = $False)]
		[ValidateSet('MD5', 'SHA1', 'SHA256', 'SHA384', 'SHA512')]
		[string]
		$Algorithm = "SHA256"
	)
	$Hash = Get-FileHash -Path $Path -Algorithm $Algorithm
	return $Hash.Hash.ToUpper()
}

function Get-LinuxRemoteFileHash {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $True)]
		[string]
		$Path,

		[Parameter(Mandatory = $True)]
		[object]
		$Session
	)
	$Hash = Invoke-Command -ScriptBlock { $Session.ExecuteCommand("sha256sum ""$Path""") }
	if ($Hash.IsSuccess -eq $False) {
		throw $Hash.ErrorOutput
	}

	$Hash = ($Hash.output -split " ")[0].ToUpper()

	return $Hash
}

function Get-UnixRemoteFileHash {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $True)]
		[string]
		$Path,

		[Parameter(Mandatory = $True)]
		[object]
		$Session
	)
	$Hash = Invoke-Command -ScriptBlock { $Session.ExecuteCommand("digest -a sha256 ""$Path""") }
	$Hash = $Hash.output.ToUpper()

	return $Hash
}

function Get-WindowsRemoteFileHash {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $True)]
		[string]
		$Path,

		[Parameter(Mandatory = $True)]
		[object]
		$Session
	)
	$Hash = Invoke-Command -ScriptBlock { $Session.ExecuteCommand("certutil.exe -hashfile ""$Path"" SHA256") }
	$Hash = $Hash.output

	return $Hash
}

function Get-RemoteFileHash {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $True)]
		[string]
		$Path,

		[Parameter(Mandatory = $True)]
		[object]
		$Session,

		[Parameter(Mandatory = $True)]
		[string]
		$HashType
	)
	$HashType = $HashType.ToUpper()

	switch ($HashType) {
		"LINUX" { $Hash = Get-LinuxRemoteFileHash -Path $Path -Session $Session }
		"UNIX" { $Hash = Get-UnixRemoteFileHash -Path $Path -Session $Session }
		"WINDOWS" { $Hash = Get-WindowsRemoteFileHash -Path $Path -Session $Session }
		Default { Throw "Invalid hash type. Hash type $HashType is not valid. The valid hash types are 'LINUX', 'UNIX' and 'WINDOWS'." }
	}

	return $Hash
}

function Test-SourceFileHashForChanges {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $True)]
		[String]
		$CurrentHash,

		[Parameter(Mandatory = $True)]
		[object]
		$Session,

		[Parameter(Mandatory = $True)]
		[string]
		$Path,

		[Parameter(Mandatory = $False)]
		[int]
		$SleepTime = 20
	)

	Start-Sleep -Seconds $SleepTime
	$NewHash = Get-LinuxRemoteFileHash -Path $Path -Session $Session

	if ($CurrentHash -ne $NewHash) {
		throw "File hashes do not match after waiting for $SleepTime seconds. File appears to be still uploading."
	}
}

function Open-Session {
	[CmdletBinding()]
	param (
		[string]$ComputerName,
		[string]$UserName,
		[string]$PrivateKeyPath,
		[string]$SessionLogPath
	)

	# Load WinSCP .NET assembly
	$DLL = Get-WinScpDll
	Add-Type -Path $DLL

	$SessionOptions = New-Object WinSCP.SessionOptions -Property @{
		Protocol              = [WinSCP.Protocol]::Sftp
		HostName              = $ComputerName
		UserName              = $UserName
		SshPrivateKeyPath     = $PrivateKeyPath
		SshHostKeyFingerprint = Get-SshFingerprint -ComputerName $ComputerName
	}

	$TransferOptions = New-Object WinSCP.TransferOptions
	$TransferOptions.TransferMode = [WinSCP.TransferMode]::Binary

	$Session = New-Object WinSCP.Session
	$SessionLog = Join-Path $SessionLogPath "$(Get-Date -Format FileDate).$ComputerName.Session.log"
	$Session.SessionLogPath = $SessionLog

	$Session.Open($SessionOptions)

	return $Session
}
function Open-FtpsSession {
	[CmdletBinding()]
	param (
		[string]$ComputerName,
		[pscredential]$Credential = (Get-Credential),
		[string]$SessionLogPath = "$Pwd\Logs\SessionLogs\$ComputerName"
	)

	# Load WinSCP .NET assembly
	$DLL = Get-WinScpDll
	Add-Type -Path $DLL

	$SessionOptions = New-Object WinSCP.SessionOptions -Property @{
		Protocol                      = [WinSCP.Protocol]::Ftp
		FtpSecure                     = [WinSCP.FtpSecure]::Explicit
		HostName                      = $ComputerName
		UserName                      = $Credential.UserName
		Password                      = $Credential.GetNetworkCredential().Password
		TlsHostCertificateFingerprint = Get-FtpsFingerprint -ComputerName $ComputerName
	}

	$TransferOptions = New-Object WinSCP.TransferOptions
	$TransferOptions.TransferMode = [WinSCP.TransferMode]::Binary

	$SessionLogPath = New-Directory -Path $SessionLogPath

	$Session = New-Object WinSCP.Session
	$SessionLog = Join-Path $SessionLogPath "$(Get-Date -Format FileDate).$ComputerName.Session.log"
	$Session.SessionLogPath = $SessionLog

	$Session.Open($SessionOptions)

	return $Session
}

Function Close-Session {
	[CmdletBinding()]
	param (
		# List of sessions to close
		[Parameter(Mandatory = $True)]
		[AllowNull()]
		[object[]]
		$Session,

		# Suppress errors when closing sessions
		[Parameter(Mandatory = $False)]
		[switch]
		$SuppressErrors
	)
	$ErrorList = @()
	foreach ($S in $Session) {
		Try {
			$S.Dispose()
		}
		Catch {
			$Err = $_
			$ErrMsg = "Failed to close session. $Err"
			$ErrorList += $ErrMsg
		}
	}
	if (-not $SuppressErrors) {
		if ($ErrorList) {
			Throw "$($ErrorList -join "\n")"
		}
	}
}

function Get-RemoteFilesList {
	[CmdletBinding()]
	param (
		[object]$Session,
		[object]$Path
	)
	$Files = $Session.EnumerateRemoteFiles($Path, "*", [WinSCP.EnumerationOptions]::None)
	return $Files
}

function Get-AzureFilesList {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[string]
		$StorageAccountName,

		[Parameter(Mandatory = $true)]
		[string]
		$StorageAccountKey,

		[Parameter(Mandatory = $true)]
		[string]
		$Container
	)

	$Context = New-AzStorageContext -StorageAccountName $StorageAccountName -StorageAccountKey $StorageAccountKey

	$Files = Get-AzStorageBlob -Context $Context -Container $Container | Where-Object { $_.name -notlike "*/*" }

	return $Files
}

function Get-WinScpDll {
	param(
		$Path = "$PSScriptRoot\bin"
	)

	# Build path for WinSCP DLL and EXE
	$DLL = Join-Path $Path "WinSCPnet.dll"
	$EXE = Join-Path $Path "WinSCP.exe"

	# Test to ensure DLL and EXE exist
	if (-not (Test-Path $DLL -PathType Leaf)) {
		throw "Unable to find WinSCP DLL at '$DLL'"
	}
	if (-not (Test-Path $EXE -PathType Leaf)) {
		throw "Unable to find WinSCP EXE at '$EXE'"
	}

	return $DLL
}

function Close-OpenFiles {
	param(
		# File path
		[Parameter(Mandatory = $true)]
		[string]
		$File
	)
	if ([string]::IsNullOrWhiteSpace($File)) {
		return
	}
	if (-not (Test-Path -LiteralPath $File -PathType Leaf)) {
		return
	}
	$OpenFiles = Get-SmbOpenFile | Where-Object { $_.Path -eq $File }
	$SessionsIds = $OpenFiles | Group-Object "sessionId" | Select-Object -ExpandProperty Name
	$SessionsIds | ForEach-Object { Close-SmbOpenFile -SessionId $_ -Force -Confirm:$False }
}

function Write-TransferLog($TransferLogEntry, $File) {
	Close-OpenFiles $File
	$TransferLogEntry | Export-Csv -NoTypeInformation -Append -LiteralPath $File
}
function Get-SshFingerprint {
	param(
		[string]$ComputerName
	)

	# Load WinSCP .NET assembly
	$DLL = Get-WinScpDll
	Add-Type -Path $DLL

	# Setup session options
	$SessionOptions = New-Object WinSCP.SessionOptions -Property @{
		Protocol = [WinSCP.Protocol]::Sftp
		HostName = $ComputerName
		UserName = ""
	}
	Get-Fingerprint -SessionOptions $SessionOptions -Algorithm "SHA-256"
}


function Get-FtpsFingerprint {
	param(
		[string]$ComputerName
	)

	# Load WinSCP .NET assembly
	$DLL = Get-WinScpDll
	Add-Type -Path $DLL

	# Setup session options
	$SessionOptions = New-Object WinSCP.SessionOptions -Property @{
		Protocol  = [WinSCP.Protocol]::Ftp
		HostName  = $ComputerName
		FtpSecure = [WinSCP.FtpSecure]::Explicit
	}
	Get-Fingerprint -SessionOptions $SessionOptions -Algorithm "SHA-1"
}

function Get-Fingerprint {
	param(
		$SessionOptions,
		$Algorithm
	)
	# Load WinSCP .NET assembly
	$DLL = Get-WinScpDll
	Add-Type -Path $DLL

	# Get fingerprint
	$Session = New-Object WinSCP.Session
	try {
		$Fingerprint = $Session.ScanFingerprint($SessionOptions, $Algorithm)
	}
	finally {
		$Session.Dispose()
	}

	# And output the host key to the pipeline
	return $Fingerprint
}

function Write-Log {
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true, Position = 0)]
		[ValidateSet('Info', 'Error', IgnoreCase = $true)]
		[string]
		$Type,

		[Parameter(Mandatory = $true, Position = 1)]
		[string]
		$Message,

		[Parameter(Mandatory = $true)]
		[string]
		$JobName
	)

	$Date = Get-Date -Format FileDate
	$LogPath = "$PSScriptRoot\logs\$JobName"
	$LogFileName = Join-Path $LogPath "$Date.log"
	if (!(Test-Path $logPath)) {
		New-Item -Type Directory $LogPath -Force | Out-Null
	}

	if (!(Test-Path $LogFileName)) {
		New-Item -Type File $LogFileName | Out-Null
		"$(Get-date -Format G) - [INFO] : -------- NEW LOG ---------" | Add-Content $LogFileName
	}

	$MaxRetries = 10
	$Counter = 0
	while ($True) {
		if ($Counter -ge $MaxRetries) {
			throw "Failed to write log file."
		}
		try {
			"$(Get-date -Format G) - [$($Type.ToUpper())] : $($Message)" | Add-Content $LogFileName
			Break
		}
		Catch {
			Write-Host "Log file is open. Sleeping 1 second and trying again."
			Close-OpenFiles($LogFileName)
			Start-Sleep -Seconds 1
			$Counter++
		}
	}
}
function New-Directory {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[string]
		$Path
	)
	if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
		New-Item -Type Directory -Path $Path -Force | Out-Null
	}
	return (Get-Item $Path).FullName
}
function RotateSessionLog {
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true,
			Position = 0)]
		[string]$path
	)
	if (Test-Path $path) {
		$logs = Get-ChildItem -Path $path -File *.log
		foreach ($log in $logs) {
			if (((Get-Date) - $log.CreationTime).Days -gt 29) {
				Remove-Item $($log.FullName) -Force
			}
		}
	}
}

function Send-Email {
	[CmdletBinding()]
	param
	(
		[string[]]$To,
		[string]$From,
		[string]$Subject,
		[string]$Body,
		[string]$SmtpServer,
		[string]$SmtpAuthCredentialPath
	)
	$from = "FTP/Azure Blob Transfer <$from>"
	if ($SmtpAuthCredentialPath -and (Test-Path $SmtpAuthCredentialPath)) {
		$cred = Import-Clixml $SmtpAuthCredentialPath
		Send-MailMessage -To $To -From $From -Subject $Subject -Body $Body -BodyAsHtml:$True -SmtpServer $SmtpServer -Credential $cred
	}
	else {
		Send-MailMessage -To $To -From $From -Subject $Subject -Body $Body -BodyAsHtml:$True -SmtpServer $SmtpServer
	}
}


function Send-SuccessEmail {
	[CmdletBinding()]
	param
	(
		[string]$JobName,
		[string]$From,
		[string[]]$To,
		[string]$Message,
		[string]$SmtpServer,
		[string]$SmtpAuthCredentialPath
	)
	$Subject = "Success - $JobName"
	Send-Email -To $To -From $From -Subject $Subject -Body $Message -SmtpServer $SmtpServer -SmtpAuthCredentialPath $SmtpAuthCredentialPath
}

function Send-FailureEmail {
	[CmdletBinding()]
	param
	(
		[string]$JobName,
		[string]$From,
		[string[]]$To,
		[string]$Message,
		[string]$SmtpServer,
		[string]$SmtpAuthCredentialPath
	)
	$Subject = "Failure - $JobName"
	Send-Email -To $To -From $From -Subject $Subject -Body $Message -SmtpServer $SmtpServer -SmtpAuthCredentialPath $SmtpAuthCredentialPath
}


Function Copy-FilesFromFtpToAzureBlob {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[string]
		$JobName,

		[Parameter(Mandatory = $true)]
		[string]
		$FtpServer,

		[Parameter(Mandatory = $true)]
		[string]
		$FtpFolder,

		[Parameter(Mandatory = $true)]
		[PSCredential]
		$FtpCredential,

		[Parameter(Mandatory = $true)]
		[string]
		$FtpSessionLogDirectory,

		[Parameter(Mandatory = $true)]
		[string]
		$TempDirectory,

		[Parameter(Mandatory = $true)]
		[string]
		$AzureStorageAccountName,

		[Parameter(Mandatory = $true)]
		[string]
		$AzureStorageAccountKey,

		[Parameter(Mandatory = $true)]
		[string]
		$AzureContainerName,

		[Parameter(Mandatory = $true)]
		[string]
		$TransferLogFile,

		[Parameter(Mandatory = $true)]
		[string[]]
		$CustomerEmail,

		[Parameter(Mandatory = $true)]
		[string[]]
		$AllEmail,

		[Parameter(Mandatory = $true)]
		[string]
		$FromEmail,

		[Parameter(Mandatory = $false)]
		[string]
		$SmtpAuthCredentialPath,

		[Parameter(Mandatory = $false)]
		[switch]
		$SendSuccessEmail,

		[Parameter(Mandatory = $false)]
		[switch]
		$DeleteFiles,

		[Parameter(Mandatory = $true)]
		[string]
		$SmtpServer
	)
	# Create FTP Session
	Write-Log -JobName $JobName -Type info -Message "Opening session to FTP server '$FtpServer'..."
	Try {
		$FtpSession = Open-FtpsSession -ComputerName $FtpServer -Credential $FtpCredential -SessionLogPath $FtpSessionLogDirectory
		Write-Log -JobName $JobName -Type info -Message "Successfully opened session to FTP server."
	}
	Catch {
		$Err = $_
		$ErrMsg = "Failed to open session to FTP server '$FtpServer'. Error: $Err"
		Write-Log -JobName $JobName -Type error -Message $ErrMsg
		Send-FailureEmail -JobName $JobName -To $AllEmail -Message $ErrMsg -SmtpServer $SmtpServer -From $FromEmail -SmtpAuthCredentialPath $SmtpAuthCredentialPath
		Close-Session -Session $FtpSession -SuppressErrors
		return
	}

	# Enumerate Files
	Write-Log -JobName $JobName -Type info -Message "Enumerating files on FTP server '$FtpServer' at path '$FtpFolder'..."
	Try {
		$Files = Get-RemoteFilesList -Session $FtpSession -Path $FtpFolder
		Write-Log -JobName $JobName -Type info -Message "Successfully enumerated files on FTP server."
		$FilesCount = $Files | Measure-Object | Select-Object -ExpandProperty Count
		Write-Log -JobName $JobName -Type info -Message "Found $FilesCount file(s) on FTP server."
	}
	Catch {
		$Err = $_
		$ErrMsg = "Failed to enumerate files on FTP server '$FtpServer'. Error: $Err"
		Write-Log -JobName $JobName -Type error -Message $ErrMsg
		Send-FailureEmail -JobName $JobName -To $AllEmail -Message $ErrMsg -SmtpServer $SmtpServer -From $FromEmail -SmtpAuthCredentialPath $SmtpAuthCredentialPath
		Close-Session -Session $FtpSession -SuppressErrors
		return
	}

	# Only continue if files are on FTP server
	if ($FilesCount -eq 0) {
		Write-Log -JobName $JobName -Type info -Message "No files found on '$FtpServer' at path '$FtpFolder'."
		Close-Session -Session $FtpSession -SuppressErrors
		return
	}

	# Loop over files
	# Any continues in this foreach loop do NOT close sessions.
	Foreach ($File in $Files) {
		$FtpFileFullName = $File.FullName
		$TempFileFullName = Join-Path $TempDirectory (New-TempFileName)
		$AzureBlobFileName = $File.Name
		$TransferLogEntry = [PSCustomObject]@{
			Date                = (Get-Date)
			Direction           = "FromFtpToAzureBlob"
			JobName             = $JobName
			FtpServer           = $FtpServer
			FtpFile             = $FtpFileFullName
			TempFile            = $TempFileFullName
			AzureStorageAccount = $AzureStorageAccountName
			AzureContainer      = $AzureContainerName
			AzureBloFile        = $AzureBlobFileName
			Status              = ""
			Error               = ""
		}

		# Log variables
		Write-Log -JobName $JobName -Type info -Message "FtpFileFullName => $FtpFileFullName"
		Write-Log -JobName $JobName -Type info -Message "TempFileFullName => $TempFileFullName"
		Write-Log -JobName $JobName -Type info -Message "AzureBlobFileName => $AzureBlobFileName"

		# Copy FTP File to tmp
		Write-Log -JobName $JobName -Type info -Message "Copying file '$FtpFileFullName' to temp file '$TempFileFullName'..."
		Try {
			$TransferOptions = $null
			$GetResults = Get-File -File $FtpFileFullName -Destination $TempFileFullName -Session $FtpSession -TransferOptions $TransferOptions -DeleteFile:$DeleteFiles
			if ($GetResults.Transfers.Length -ne 1) {
				Throw "Number of files transferred is not equal to 1."
			}
			Write-Log -JobName $JobName -Type info -Message "Successfully copied file."
		}
		Catch {
			$Err = $_
			$ErrMsg = "Failed to copy FTP file '$FtpFileFullName' to temp file '$TempFileFullName'. Error: $Err"
			Write-Log -JobName $JobName -Type error -Message $ErrMsg
			Send-FailureEmail -JobName $JobName -To $AllEmail -Message $ErrMsg -SmtpServer $SmtpServer -From $FromEmail -SmtpAuthCredentialPath $SmtpAuthCredentialPath
			$TransferLogEntry.Status = "Failed"
			$TransferLogEntry.Error = $ErrMsg
			Write-TransferLog -TransferLogEntry $TransferLogEntry -File $TransferLogFile
			Continue
		}

		# Copy temp file to Azure blob
		Write-Log -JobName $JobName -Type info -Message "Copying temp file '$TempFileFullName' to Azure storage account named '$AzureStorageAccountName' in container '$AzureContainerName' file named '$AzureBlobFileName'..."
		Try {
			$PushResults = Push-AzureBlobFile -StorageAccountName $AzureStorageAccountName -StorageAccountKey $AzureStorageAccountKey -Container $AzureContainerName -SourceFileFullPath $TempFileFullName -DestinationFileName $AzureBlobFileName -DeleteFile:$DeleteFiles
			$PushResultsCount = $PushResults | Measure-Object | Select-Object -ExpandProperty Count
			if ($PushResultsCount -ne 1) {
				Throw "Number of files transferred is not equal to 1."
			}
			Write-Log -JobName $JobName -Type info -Message "Successfully copied file."
		}
		Catch {
			$Err = $_
			$ErrMsg = "Failed to copy temp file '$TempFileFullName' to Azure storage account named '$AzureStorageAccountName' in container '$AzureContainerName' file named '$AzureBlobFileName'. Error: $Err"
			Write-Log -JobName $JobName -Type error -Message $ErrMsg
			Send-FailureEmail -JobName $JobName -To $AllEmail -Message $ErrMsg -SmtpServer $SmtpServer -From $FromEmail -SmtpAuthCredentialPath $SmtpAuthCredentialPath
			$TransferLogEntry.Status = "Failed"
			$TransferLogEntry.Error = $ErrMsg
			Write-TransferLog -TransferLogEntry $TransferLogEntry -File $TransferLogFile
			Continue
		}

		# Write successful transfer log entry
		$TransferLogEntry.Status = "Success"
		$TransferLogEntry.Error = ""
		Write-TransferLog -TransferLogEntry $TransferLogEntry -File $TransferLogFile

		# Email success
		if ($SendSuccessEmail) {
			Write-Log -JobName $JobName -Type info -Message "Sending success email..."
			Send-SuccessEmail -JobName $JobName -To $CustomerEmail -Message "File '$AzureBlobFileName' was successfully transferred to Azure storage account named '$AzureStorageAccountName' in container '$AzureContainerName'." -SmtpServer $SmtpServer -From $FromEmail -SmtpAuthCredentialPath $SmtpAuthCredentialPath
			Write-Log -JobName $JobName -Type info -Message "Successfully sent email."
		}
	}

	# Close FTP Session
	Write-Log -JobName $JobName -Type info -Message "Closing session to FTP server '$FtpServer'..."
	Try {
		Close-Session -Session $FtpSession
		Write-Log -JobName $JobName -Type info -Message "Successfully closed session."
	}
	Catch {
		$Err = $_
		$ErrMsg = "Failed to close session to FTP server '$FtpServer'. Error: $Err"
		Write-Log -JobName $JobName -Type error -Message $ErrMsg
		Send-FailureEmail -JobName $JobName -To $AdminEmail -Message $ErrMsg -SmtpServer $SmtpServer -From $FromEmail -SmtpAuthCredentialPath $SmtpAuthCredentialPath
	}
}

Function Copy-FilesFromAzureBlobToFtp {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[string]
		$JobName,

		[Parameter(Mandatory = $true)]
		[string]
		$FtpServer,

		[Parameter(Mandatory = $true)]
		[string]
		$FtpFolder,

		[Parameter(Mandatory = $true)]
		[PSCredential]
		$FtpCredential,

		[Parameter(Mandatory = $true)]
		[string]
		$FtpSessionLogDirectory,

		[Parameter(Mandatory = $true)]
		[string]
		$TempDirectory,

		[Parameter(Mandatory = $true)]
		[string]
		$AzureStorageAccountName,

		[Parameter(Mandatory = $true)]
		[string]
		$AzureStorageAccountKey,

		[Parameter(Mandatory = $true)]
		[string]
		$AzureContainerName,

		[Parameter(Mandatory = $true)]
		[string]
		$TransferLogFile,

		[Parameter(Mandatory = $true)]
		[string[]]
		$CustomerEmail,

		[Parameter(Mandatory = $true)]
		[string[]]
		$AllEmail,

		[Parameter(Mandatory = $true)]
		[string]
		$FromEmail,

		[Parameter(Mandatory = $false)]
		[string]
		$SmtpAuthCredentialPath,

		[Parameter(Mandatory = $false)]
		[switch]
		$SendSuccessEmail,

		[Parameter(Mandatory = $false)]
		[switch]
		$DeleteFiles,

		[Parameter(Mandatory = $true)]
		[string]
		$SmtpServer
	)

	# Enumerate Files in Azure blob
	Write-Log -JobName $JobName -Type info -Message "Enumerating files on Azure Storage account '$AzureStorageAccountName' in container '$AzureContainerName'..."
	Try {
		$Files = Get-AzureFilesList -Container $AzureContainerName -StorageAccountName $AzureStorageAccountName -StorageAccountKey $AzureStorageAccountKey
		Write-Log -JobName $JobName -Type info -Message "Successfully enumerated files on Azure storage account container."
		$FilesCount = $Files | Measure-Object | Select-Object -ExpandProperty Count
		Write-Log -JobName $JobName -Type info -Message "Found $FilesCount file(s) in Azure storage account container."
	}
	Catch {
		$Err = $_
		$ErrMsg = "Failed to enumerate files on Azure Storage account '$AzureStorageAccountName' in container '$AzureContainerName'. Error: $Err"
		Write-Log -JobName $JobName -Type error -Message $ErrMsg
		Send-FailureEmail -JobName $JobName -To $AllEmail -Message $ErrMsg -SmtpServer $SmtpServer -From $FromEmail -SmtpAuthCredentialPath $SmtpAuthCredentialPath
		return
	}

	# Only continue if files are in Azure blob
	if ($FilesCount -eq 0) {
		Write-Log -JobName $JobName -Type info -Message "No files found on Azure Storage account '$AzureStorageAccountName' in container '$AzureContainerName'."
		return
	}

	# Create FTP Session
	Write-Log -JobName $JobName -Type info -Message "Opening session to FTP server '$FtpServer'..."
	Try {
		$FtpSession = Open-FtpsSession -ComputerName $FtpServer -Credential $FtpCredential -SessionLogPath $FtpSessionLogDirectory
		Write-Log -JobName $JobName -Type info -Message "Successfully opened session to FTP server."
	}
	Catch {
		$Err = $_
		$ErrMsg = "Failed to open session to FTP server '$FtpServer'. Error: $Err"
		Write-Log -JobName $JobName -Type error -Message $ErrMsg
		Send-FailureEmail -JobName $JobName -To $AllEmail -Message $ErrMsg -SmtpServer $SmtpServer -From $FromEmail -SmtpAuthCredentialPath $SmtpAuthCredentialPath
		Close-Session -Session $FtpSession -SuppressErrors
		return
	}

	# Loop over files
	# Any continues in this foreach loop do NOT close sessions.
	Foreach ($File in $Files) {
		$AzureBlobFileName = $File.Name
		$TempFileFullName = Join-Path $TempDirectory (New-TempFileName)
		$FtpFileFullName = "$($FtpFolder.TrimEnd('/'))/$AzureBlobFileName"
		$TransferLogEntry = [PSCustomObject]@{
			Date                = (Get-Date)
			Direction           = "FromAzureBlobToFtp"
			JobName             = $JobName
			FtpServer           = $FtpServer
			FtpFile             = $FtpFileFullName
			TempFile            = $TempFileFullName
			AzureStorageAccount = $AzureStorageAccountName
			AzureContainer      = $AzureContainerName
			AzureBloFile        = $AzureBlobFileName
			Status              = ""
			Error               = ""
		}

		# Log variables
		Write-Log -JobName $JobName -Type info -Message "AzureBlobFileName => $AzureBlobFileName"
		Write-Log -JobName $JobName -Type info -Message "TempFileFullName => $TempFileFullName"
		Write-Log -JobName $JobName -Type info -Message "FtpFileFullName => $FtpFileFullName"

		# Copy Azure blob Files to tmp
		Write-Log -JobName $JobName -Type info -Message "Copying file '$AzureBlobFileName' from Azure storage account '$AzureStorageAccountName' in container '$AzureContainerName' to temp file '$TempFileFullName'..."
		Try {
			# $TransferOptions = $null
			# $GetResults = Get-File -File $FtpFileFullName -Destination $TempFileFullName -Session $FtpSession -TransferOptions $TransferOptions -DeleteFile:$DeleteFiles
			$GetResults = Get-AzureBlobFile -StorageAccountName $AzureStorageAccountName -StorageAccountKey $AzureStorageAccountKey -Container $AzureContainerName -SourceFileName $AzureBlobFileName -DestinationFileFullPath $TempFileFullName -DeleteFile:$DeleteFiles
			$GetResultsCount = $GetResults | Measure-Object | Select-Object -ExpandProperty Count
			if ($GetResultsCount -ne 1) {
				Throw "Number of files transferred is not equal to 1."
			}
			Write-Log -JobName $JobName -Type info -Message "Successfully copied file."
		}
		Catch {
			$Err = $_
			$ErrMsg = "Failed to copy file '$AzureBlobFileName' from Azure storage account '$AzureStorageAccountName' in container '$AzureContainerName' to temp file '$TempFileFullName'. Error: $Err"
			Write-Log -JobName $JobName -Type error -Message $ErrMsg
			Send-FailureEmail -JobName $JobName -To $AllEmail -Message $ErrMsg -SmtpServer $SmtpServer -From $FromEmail -SmtpAuthCredentialPath $SmtpAuthCredentialPath
			$TransferLogEntry.Status = "Failed"
			$TransferLogEntry.Error = $ErrMsg
			Write-TransferLog -TransferLogEntry $TransferLogEntry -File $TransferLogFile
			Continue
		}

		# Copy temp file to FTP server
		Write-Log -JobName $JobName -Type info -Message "Copying temp file '$TempFileFullName' to FTP server '$FtpServer' with file name '$FtpFileFullName'..."
		Try {
			$TransferOptions = New-TransferOptions -FilePermissions '644'
			$PushResults = Push-File -File $TempFileFullName -Destination $FtpFileFullName -Session $FtpSession -TransferOptions $TransferOptions -DeleteFile:$DeleteFiles
			if ($PushResults.Transfers.Length -ne 1) {
				Throw "Number of files transferred is not equal to 1."
			}
			Write-Log -JobName $JobName -Type info -Message "Successfully copied file."
		}
		Catch {
			$Err = $_
			$ErrMsg = "Failed to copy temp file '$TempFileFullName' to FTP server '$FtpServer' with file name '$FtpFileFullName'. Error: $Err"
			Write-Log -JobName $JobName -Type error -Message $ErrMsg
			Send-FailureEmail -JobName $JobName -To $AllEmail -Message $ErrMsg -SmtpServer $SmtpServer -From $FromEmail -SmtpAuthCredentialPath $SmtpAuthCredentialPath
			$TransferLogEntry.Status = "Failed"
			$TransferLogEntry.Error = $ErrMsg
			Write-TransferLog -TransferLogEntry $TransferLogEntry -File $TransferLogFile
			Continue
		}

		# Write successful transfer log entry
		$TransferLogEntry.Status = "Success"
		$TransferLogEntry.Error = ""
		Write-TransferLog -TransferLogEntry $TransferLogEntry -File $TransferLogFile

		# Email success
		if ($SendSuccessEmail) {
			Write-Log -JobName $JobName -Type info -Message "Sending success email..."
			Send-SuccessEmail -JobName $JobName -To $CustomerEmail -Message "File '$FtpFileFullName' was successfully transferred to FTP server '$FtpServer'." -SmtpServer $SmtpServer -From $FromEmail -SmtpAuthCredentialPath $SmtpAuthCredentialPath
			Write-Log -JobName $JobName -Type info -Message "Successfully sent email."
		}
	}

	# Close FTP Session
	Write-Log -JobName $JobName -Type info -Message "Closing session to FTP server $FtpServer..."
	Try {
		Close-Session -Session $FtpSession
		Write-Log -JobName $JobName -Type info -Message "Successfully closed session."
	}
	Catch {
		$Err = $_
		$ErrMsg = "Failed to close session to FTP server $FtpServer. Error: $Err"
		Write-Log -JobName $JobName -Type error -Message $ErrMsg
		Send-FailureEmail -JobName $JobName -To $AdminEmail -Message $ErrMsg -SmtpServer $SmtpServer -From $FromEmail -SmtpAuthCredentialPath $SmtpAuthCredentialPath
	}
}

Function Copy-MFFileFromFtpToAzureBlob {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[string]
		$JobName,

		[Parameter(Mandatory = $true)]
		[string]
		$FtpServer,

		[Parameter(Mandatory = $true)]
		[string]
		$FtpFolder,

		[Parameter(Mandatory = $true)]
		[string]
		$FtpFile,

		[Parameter(Mandatory = $true)]
		[PSCredential]
		$FtpCredential,

		[Parameter(Mandatory = $true)]
		[string]
		$FtpSessionLogDirectory,

		[Parameter(Mandatory = $true)]
		[string]
		$TempDirectory,

		[Parameter(Mandatory = $true)]
		[string]
		$AzureStorageAccountName,

		[Parameter(Mandatory = $true)]
		[string]
		$AzureStorageAccountKey,

		[Parameter(Mandatory = $true)]
		[string]
		$AzureContainerName,

		[Parameter(Mandatory = $true)]
		[string]
		$AzureFileName,

		[Parameter(Mandatory = $true)]
		[string]
		$TransferLogFile,

		[Parameter(Mandatory = $true)]
		[string[]]
		$CustomerEmail,

		[Parameter(Mandatory = $true)]
		[string[]]
		$AllEmail,

		[Parameter(Mandatory = $true)]
		[string]
		$FromEmail,

		[Parameter(Mandatory = $false)]
		[string]
		$SmtpAuthCredentialPath,

		[Parameter(Mandatory = $false)]
		[switch]
		$SendSuccessEmail,

		[Parameter(Mandatory = $false)]
		[switch]
		$DeleteFiles,

		[Parameter(Mandatory = $true)]
		[string]
		$SmtpServer,

		[Parameter(Mandatory = $false)]
		[string]
		$WinScpComFile = ".\bin\WinSCP.com"
	)
	$TempFileFullName = Join-Path $TempDirectory (New-TempFileName)
	$TempScriptFullName = Join-Path $TempDirectory (New-TempFileName -Extension ".txt")
	$TransferLogEntry = [PSCustomObject]@{
		Date                = (Get-Date)
		Direction           = "FromFtpToAzureBlob"
		JobName             = $JobName
		FtpServer           = $FtpServer
		FtpFolder           = $FtpFolder
		FtpFile             = $FtpFile
		TempFile            = $TempFileFullName
		AzureStorageAccount = $AzureStorageAccountName
		AzureContainer      = $AzureContainerName
		AzureBloFile        = $AzureFileName
		Status              = ""
		Error               = ""
	}

	# Log variables
	Write-Log -JobName $JobName -Type info -Message "TempFileFullName => $TempFileFullName"
	Write-Log -JobName $JobName -Type info -Message "TempScriptFullName => $TempScriptFullName"

	# Check for a successful previous transfer
	Write-Log -JobName $JobName -Type info -Message "Checking if file '$FtpFile' was already successfully transferred today..."
	Try {
		if (Test-Path -LiteralPath $TransferLogFile) {
			$Results = Import-Csv -LiteralPath $TransferLogFile | Where-Object { (Get-Date $_.Date) -gt (Get-Date).Date } | Where-Object { $_.FtpFile -eq $FtpFile -and $_.Status -eq "Success" }
			$ResultsCount = $Results | Measure-Object | Select-Object -ExpandProperty Count
			if($ResultsCount -ge 1){
				Write-Log -JobName $JobName -Type info -Message "File was already transferred successfully."
				return
			}
			else{
				Write-Log -JobName $JobName -Type info -Message "File has not been transferred today."
			}
		}
	}
	Catch {
		$Err = $_
		$ErrMsg = "Failed to check if file '$FtpFile' was already transferred. Error: $Err"
		Write-Log -JobName $JobName -Type error -Message $ErrMsg
		Send-FailureEmail -JobName $JobName -To $AdminEmail -Message $ErrMsg -SmtpServer $SmtpServer -From $FromEmail -SmtpAuthCredentialPath $SmtpAuthCredentialPath
		$TransferLogEntry.Status = "Failed"
		$TransferLogEntry.Error = $ErrMsg
		Write-TransferLog -TransferLogEntry $TransferLogEntry -File $TransferLogFile
		Remove-MFFtpTransferScript -ScriptFile $TempScriptFullName
		return
	}

	# Create FTP File Script
	Write-Log -JobName $JobName -Type info -Message "Creating script file '$TempScriptFullName' to transfer FTP file '$FtpFile' to temp file '$TempFileFullName'..."
	Try {
		New-MFGetFileTransferScript -Credential $FtpCredential -ComputerName $FtpServer -FtpDirectory $FtpFolder -FtpFile $FtpFile -DestinationFullName $TempFileFullName -ScriptOutputFullName $TempScriptFullName -DeleteFile:$DeleteFiles
		Write-Log -JobName $JobName -Type info -Message "Successfully created script file."
	}
	Catch {
		$Err = $_
		$ErrMsg = "Failed to create script file '$TempScriptFullName' to transfer FTP file '$FtpFile' to temp file '$TempFileFullName'. Error: $Err"
		Write-Log -JobName $JobName -Type error -Message $ErrMsg
		Send-FailureEmail -JobName $JobName -To $AllEmail -Message $ErrMsg -SmtpServer $SmtpServer -From $FromEmail -SmtpAuthCredentialPath $SmtpAuthCredentialPath
		$TransferLogEntry.Status = "Failed"
		$TransferLogEntry.Error = $ErrMsg
		Write-TransferLog -TransferLogEntry $TransferLogEntry -File $TransferLogFile
		Remove-MFFtpTransferScript -ScriptFile $TempScriptFullName
		return
	}

	# Copy FTP File to tmp
	Write-Log -JobName $JobName -Type info -Message "Copying file '$FtpFile' to temp file '$TempFileFullName'..."
	Try {
		# Run transfer script
		Invoke-MFFtpTransferScript -WinSCPComFile $WinScpComFile -FtpSessionLogDirectory $FtpSessionLogDirectory -ScriptFile $TempScriptFullName -ComputerName $FtpServer
		Remove-MFFtpTransferScript -ScriptFile $TempScriptFullName
		Write-Log -JobName $JobName -Type info -Message "Successfully copied file."
	}
	Catch {
		$Err = $_
		$ErrMsg = "Failed to copy FTP file '$FtpFile' to temp file '$TempFileFullName'. Error: $Err"
		Write-Log -JobName $JobName -Type error -Message $ErrMsg
		Send-FailureEmail -JobName $JobName -To $AllEmail -Message $ErrMsg -SmtpServer $SmtpServer -From $FromEmail -SmtpAuthCredentialPath $SmtpAuthCredentialPath
		$TransferLogEntry.Status = "Failed"
		$TransferLogEntry.Error = $ErrMsg
		Write-TransferLog -TransferLogEntry $TransferLogEntry -File $TransferLogFile
		Remove-MFFtpTransferScript -ScriptFile $TempScriptFullName
		return
	}

	# Copy temp file to Azure blob
	Write-Log -JobName $JobName -Type info -Message "Copying temp file '$TempFileFullName' to Azure storage account named '$AzureStorageAccountName' in container '$AzureContainerName' file named '$AzureFileName'..."
	Try {
		$PushResults = Push-AzureBlobFile -StorageAccountName $AzureStorageAccountName -StorageAccountKey $AzureStorageAccountKey -Container $AzureContainerName -SourceFileFullPath $TempFileFullName -DestinationFileName $AzureFileName -DeleteFile:$true
		$PushResultsCount = $PushResults | Measure-Object | Select-Object -ExpandProperty Count
		if ($PushResultsCount -ne 1) {
			Throw "Number of files transferred is not equal to 1."
		}
		Write-Log -JobName $JobName -Type info -Message "Successfully copied file."
	}
	Catch {
		$Err = $_
		$ErrMsg = "Failed to copy temp file '$TempFileFullName' to Azure storage account named '$AzureStorageAccountName' in container '$AzureContainerName' file named '$AzureFileName'. Error: $Err"
		Write-Log -JobName $JobName -Type error -Message $ErrMsg
		Send-FailureEmail -JobName $JobName -To $AllEmail -Message $ErrMsg -SmtpServer $SmtpServer -From $FromEmail -SmtpAuthCredentialPath $SmtpAuthCredentialPath
		$TransferLogEntry.Status = "Failed"
		$TransferLogEntry.Error = $ErrMsg
		Write-TransferLog -TransferLogEntry $TransferLogEntry -File $TransferLogFile
		return
	}

	# Write successful transfer log entry
	$TransferLogEntry.Status = "Success"
	$TransferLogEntry.Error = ""
	Write-TransferLog -TransferLogEntry $TransferLogEntry -File $TransferLogFile

	# Email success
	if ($SendSuccessEmail) {
		Write-Log -JobName $JobName -Type info -Message "Sending success email..."
		Send-SuccessEmail -JobName $JobName -To $CustomerEmail -Message "File '$AzureFileName' was successfully transferred to Azure storage account named '$AzureStorageAccountName' in container '$AzureContainerName'." -SmtpServer $SmtpServer -From $FromEmail -SmtpAuthCredentialPath $SmtpAuthCredentialPath
		Write-Log -JobName $JobName -Type info -Message "Successfully sent email."
	}
}
