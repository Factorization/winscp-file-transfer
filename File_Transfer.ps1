<#
 .Synopsis
	A brief description of the script

 .Description
	A detailed description of the script

 .Parameter Parameter1
	A string value parameter, with a default value of 'Default String Value'

 .Example
	Example of Parameter1

 .Example
	Example of Parameter2

 .Example
	Example of Int

 .Notes
	Place Notes here

	#######################################################
	#  .                                               .  #
	#  .                Written By:                    .  #
	#.....................................................#
	#  .              Jeffrey Kraemer                  .  #
	#  .                  ENS, Inc.                    .  #
	#  .            jkraemer@ens-inc.com               .  #
	#.....................................................#
	#  .                                               .  #
	#######################################################
#>

[CmdletBinding()]
Param(

    # Job Name
    [Parameter(Mandatory = $True, ValueFromPipeline = $False)]
    [String]
    $JobName,

    # FTP Server
    [Parameter(Mandatory = $True, ValueFromPipeline = $False)]
    [String]
    $FtpServer,

    # FTP Folder
    [Parameter(Mandatory = $True, ValueFromPipeline = $False)]
    [String]
    $FtpFolder,

    # FTP Credential File Path
    [Parameter(Mandatory = $True, ValueFromPipeline = $False)]
    [string]
    $FtpCredentialPath,

    # Azure Storage Account Name
    [Parameter(Mandatory = $True, ValueFromPipeline = $False)]
    [String]
    $AzureStorageAccountName,

    # Azure Container Name
    [Parameter(Mandatory = $True, ValueFromPipeline = $False)]
    [String]
    $AzureContainerName,

    # Azure Blob Key File Path
    [Parameter(Mandatory = $True, ValueFromPipeline = $False)]
    [String]
    $AzureBlobKeyPath,

    # Direction (FromFtpToAzureBlob or FromAzureBlobToFtp)
    [Parameter(Mandatory = $True, ValueFromPipeline = $False)]
    [ValidateSet("FromFtpToAzureBlob", "FromAzureBlobToFtp")]
    [String]
    $Direction,

    # Customer Email Addresses
    [Parameter(Mandatory = $True, ValueFromPipeline = $False)]
    [String[]]
    $CustomerEmail,

    # Admin Email Addresses
    [Parameter(Mandatory = $True, ValueFromPipeline = $False)]
    [String[]]
    $AdminEmail,

    # Admin Email Addresses
    [Parameter(Mandatory = $True, ValueFromPipeline = $False)]
    [String]
    $FromEmail,

    # Email mail server
    [Parameter(Mandatory = $True, ValueFromPipeline = $False)]
    [string]
    $SmtpServer,

    # Email Auth
    [Parameter(Mandatory = $False, ValueFromPipeline = $False)]
    [string]
    $SmtpAuthCredentialPath = "",

    # Send success email
    [Parameter(Mandatory = $False, ValueFromPipeline = $False)]
    [switch]
    $SendSuccessEmail,

    # Keep all files
    [Parameter(Mandatory = $False, ValueFromPipeline = $False)]
    [switch]
    $KeepFiles
)

BEGIN {
    $ErrorActionPreference = 'Stop'

    # Import Functions
    . $PSScriptRoot\Functions.ps1

    ###### GLOBAL VARIABLES ######
    $CurrentDirectory = $PSScriptRoot
    $LogDirectory = "$CurrentDirectory\logs\$JobName"
    $TempDirectory = "$CurrentDirectory\tmp\$JobName"
    $FtpSessionLogDirectory = Join-Path $LogDirectory "ftp_session"
    $TransferLogFile = Join-Path $LogDirectory "$($JobName)_Transfer_Log.csv"
    $DeleteFiles = -not $KeepFiles
    $AllEmail = @($AdminEmail) + @($CustomerEmail)

    # Start Logging
    Write-Log -JobName $JobName -Type info -Message "Script start..."
    Write-Log -JobName $JobName -Type info -Message "JobName => $JobName"
    Write-Log -JobName $JobName -Type info -Message "FtpServer => $FtpServer"
    Write-Log -JobName $JobName -Type info -Message "FtpFolder => $FtpFolder"
    Write-Log -JobName $JobName -Type info -Message "FTPCredentialPath => $FTPCredentialPath"
    Write-Log -JobName $JobName -Type info -Message "AzureStorageAccountName => $AzureStorageAccountName"
    Write-Log -JobName $JobName -Type info -Message "AzureContainerName => $AzureContainerName"
    Write-Log -JobName $JobName -Type info -Message "AzureBlobKeyPath => $AzureBlobKeyPath"
    Write-Log -JobName $JobName -Type info -Message "Direction => $Direction"

    Write-Log -JobName $JobName -Type info -Message "CustomerEmail => $CustomerEmail"
    Write-Log -JobName $JobName -Type info -Message "AdminEmail => $AdminEmail"
    Write-Log -JobName $JobName -Type info -Message "AllEmail => $AllEmail"
    Write-Log -JobName $JobName -Type info -Message "FromEmail => $FromEmail"
    Write-Log -JobName $JobName -Type info -Message "SmtpServer => $SmtpServer"
    Write-Log -JobName $JobName -Type info -Message "SmtpAuthCredentialPath => $SmtpAuthCredentialPath"
    Write-Log -JobName $JobName -Type info -Message "SendSuccessEmail => $SendSuccessEmail"

    Write-Log -JobName $JobName -Type info -Message "KeepFiles => $KeepFiles"

    Write-Log -JobName $JobName -Type info -Message "CurrentDirectory => $CurrentDirectory"
    Write-Log -JobName $JobName -Type info -Message "LogDirectory => $LogDirectory"
    Write-Log -JobName $JobName -Type info -Message "TempDirectory => $TempDirectory"
    Write-Log -JobName $JobName -Type info -Message "FtpSessionLogDirectory => $FtpSessionLogDirectory"
    Write-Log -JobName $JobName -Type info -Message "TransferLogFile => $TransferLogFile"
    Write-Log -JobName $JobName -Type info -Message "DeleteFiles => $DeleteFiles"

    # Create Required Directories
    $RequiredDirectories = @(
        $LogDirectory,
        $TempDirectory,
        $FtpSessionLogDirectory
    )
    foreach ($Dir in $RequiredDirectories) {
        Try {
            Write-Log -JobName $JobName -Type info -Message "Creating directory '$Dir'..."
            New-Item -Type Directory -Path $Dir -Force | Out-Null
            Write-Log -JobName $JobName -Type info -Message "Successfully created directory."
        }
        Catch {
            $Err = $_
            $ErrMsg = "Failed to create directory '$Dir'. Error: $Err"
            Write-Log -JobName $JobName -Type error -Message $ErrMsg
            Send-FailureEmail -JobName $JobName -To $AdminEmail -Message $ErrMsg -SmtpServer $SmtpServer  -From $FromEmail -SmtpAuthCredentialPath $SmtpAuthCredentialPath
            Exit
        }
    }

    # Verify Required files
    $RequiredFiles = @(
        "$CurrentDirectory\bin\WinSCP.exe",
        "$CurrentDirectory\bin\WinSCPnet.dll",
        $AzureBlobKeyPath,
        $FTPCredentialPath
    )
    Foreach ($File in $RequiredFiles) {
        Write-Log -JobName $JobName -Type info -Message "Verifying file '$File' exists..."
        if (-not (Test-Path -LiteralPath $File -PathType Leaf)) {
            $ErrMsg = "File '$File' does not exist."
            Write-Log -JobName $JobName -Type error -Message $ErrMsg
            Send-FailureEmail -JobName $JobName -To $AdminEmail -Message $ErrMsg -SmtpServer $SmtpServer -From $FromEmail -SmtpAuthCredentialPath $SmtpAuthCredentialPath
            Exit
        }
        Write-Log -JobName $JobName -Type info -Message "File exists."
    }

    # Import Credentials
    Write-Log -JobName $JobName -Type info -Message "Importing FTP credential from '$FTPCredentialPath'..."
    Try {
        $FtpCredential = Import-Clixml $FtpCredentialPath
        Write-Log -JobName $JobName -Type info -Message "Successfully imported FTP credential."
    }
    Catch {
        $Err = $_
        $ErrMsg = "Failed to import FTP credential from '$FtpCredentialPath'. Error: $Err"
        Write-Log -JobName $JobName -Type error -Message $ErrMsg
        Send-FailureEmail -JobName $JobName -To $AdminEmail -Message $ErrMsg -SmtpServer $SmtpServer -From $FromEmail -SmtpAuthCredentialPath $SmtpAuthCredentialPath
        Exit
    }
    Write-Log -JobName $JobName -Type info -Message "Importing Azure blob key from '$AzureBlobKeyPath'..."
    Try {
        $AzureBlobKey = (Import-Clixml $AzureBlobKeyPath).GetNetworkCredential().Password
        Write-Log -JobName $JobName -Type info -Message "Successfully imported Azure blob key."
    }
    Catch {
        $Err = $_
        $ErrMsg = "Failed to import Azure blob key from '$AzureBlobKeyPath'. Error: $Err"
        Write-Log -JobName $JobName -Type error -Message $ErrMsg
        Send-FailureEmail -JobName $JobName -To $AdminEmail -Message $ErrMsg -SmtpServer $SmtpServer -From $FromEmail -SmtpAuthCredentialPath $SmtpAuthCredentialPath
        Exit
    }

    # Rotate WinSCP session log
    Write-Log -JobName $JobName -Type info -Message "Rotating WinSCP session logs..."
    Try {
        RotateSessionLog $FtpSessionLogDirectory
        Write-Log -JobName $JobName -Type info -Message "Successfully rotated WinSCP session logs."
    }
    Catch {
        $Err = $_
        $ErrMsg = "Failed to rotate session logs. Error: $Err"
        Write-Log -JobName $JobName -Type error -Message $ErrMsg
        Send-FailureEmail -JobName $JobName -To $AdminEmail -Message $ErrMsg -SmtpServer $SmtpServer -From $FromEmail -From $FromEmail -SmtpAuthCredentialPath $SmtpAuthCredentialPath
    }
}
PROCESS {
    Try {
        if ($Direction -eq "FromFtpToAzureBlob") {
            Copy-FilesFromFtpToAzureBlob -JobName $JobName -FtpServer $FtpServer -FtpFolder $FtpFolder `
                -FtpCredential $FtpCredential -FtpSessionLogDirectory $FtpSessionLogDirectory -TempDirectory $TempDirectory `
                -AzureStorageAccountName $AzureStorageAccountName -AzureStorageAccountKey $AzureBlobKey -AzureContainerName $AzureContainerName `
                -TransferLogFile $TransferLogFile -CustomerEmail $CustomerEmail -AllEmail $AllEmail -SendSuccessEmail:$SendSuccessEmail `
                -DeleteFiles:$DeleteFiles -SmtpServer $SmtpServer -FromEmail $FromEmail
        }
        elseif ($Direction -eq "FromAzureBlobToFtp") {

        }
        else {
            $ErrMsg = "Invalid direction '$Direction'. Exiting."
            Write-Log -JobName $JobName -Type error -Message $ErrMsg
            Send-FailureEmail -JobName $JobName -To $AdminEmail -Message $ErrMsg -SmtpServer $SmtpServer -From $FromEmail -SmtpAuthCredentialPath $SmtpAuthCredentialPath
            Close-Session -Session $SourceSession -SuppressErrors
            Exit
        }
    }
    Catch {
        $Err = $_
        $ErrMsg = "Unhandled exception. Error: $Err"
        Write-Log -JobName $JobName -Type error -Message $ErrMsg
        Send-FailureEmail -JobName $JobName -To $AdminEmail -Message $ErrMsg -SmtpServer $SmtpServer -From $FromEmail -SmtpAuthCredentialPath $SmtpAuthCredentialPath
    }
    Finally {
        Write-Log -JobName $JobName -Type info -Message "Closing any open sessions..."
        Close-Session -Session $SourceSession, $DestinationSession -SuppressErrors
        Write-Log -JobName $JobName -Type info -Message "Done closing sessions."
    }
}
END {
    Write-Log -JobName $JobName -Type info -Message "Script end."
}
