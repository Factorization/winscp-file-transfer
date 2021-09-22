Function New-TempFileName {
	[CmdletBinding()]
	param (
	)
	$Guid = (New-Guid).Guid
	$FileName = $Guid + ".tmp"
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
		[string]$SessionLogPath = "$PSScriptRoot\Logs\SessionLogs\$ComputerName"
	)

	# Load WinSCP .NET assembly
	$DLL = Get-WinScpDll
	Add-Type -Path $DLL

	$SessionOptions = New-Object WinSCP.SessionOptions -Property @{
		Protocol              = [WinSCP.Protocol]::Ftp
		FtpSecure             = [WinSCP.FtpSecure]::Explicit
		HostName              = $ComputerName
		UserName              = $Credential.UserName
		Password 			  = $Credential.GetNetworkCredential().Password
		SshHostKeyFingerprint = Get-FtpsFingerprint -ComputerName $ComputerName
	}

	$TransferOptions = New-Object WinSCP.TransferOptions
	$TransferOptions.TransferMode = [WinSCP.TransferMode]::Binary

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
		[string]$Type,

		[Parameter(Position = 1)]
		[string]$Message
	)

	$Date = Get-Date -Format FileDate
	$LogPath = "$PSScriptRoot\logs"
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
