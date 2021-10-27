<#
 .Synopsis
	A script to transfer files from a Mainframe FTP server to Azure blob storage or from Azure blob storage to a Mainframe FTP server.

 .Description
	This script uses the WinSCP COM and the Azure az.storage module to copy files from Mainframe FTP to Azure blob storage and vice versa.


 .Example


 .Example

 .Notes
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

    # Arbitrary name to track the job
    [Parameter(Mandatory = $True, ValueFromPipeline = $False)]
    [String]
    $JobName,

    # FTP Server FQDN or IP
    [Parameter(Mandatory = $True, ValueFromPipeline = $False)]
    [String]
    $FtpServer,

    # FTP Folder path using Mainframe format ('PATH.TO.FOLDER')
    [Parameter(Mandatory = $True, ValueFromPipeline = $False)]
    [String]
    $FtpFolder,

    # FTP File Name
    [Parameter(Mandatory = $True, ValueFromPipeline = $False)]
    [String]
    $FtpFile,

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

    # Azure File Name
    [Parameter(Mandatory = $True, ValueFromPipeline = $False)]
    [String]
    $AzureFileName,

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

    # From Email Addresses
    [Parameter(Mandatory = $True, ValueFromPipeline = $False)]
    [String]
    $FromEmail,

    # Email mail server
    [Parameter(Mandatory = $True, ValueFromPipeline = $False)]
    [string]
    $SmtpServer,

    # Email Auth Credential File Path
    [Parameter(Mandatory = $False, ValueFromPipeline = $False)]
    [string]
    $SmtpAuthCredentialPath = "",

    # Send success emails
    [Parameter(Mandatory = $False, ValueFromPipeline = $False)]
    [switch]
    $SendSuccessEmail,

    # Keep files on source
    [Parameter(Mandatory = $False, ValueFromPipeline = $False)]
    [switch]
    $KeepFiles
)
#Requires -RunAsAdministrator
#Requires -Modules az.storage

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
    $AllEmail = @()
    $AllEmail += @($AdminEmail)
    $AllEmail += @($CustomerEmail)

    # Start Logging
    Write-Log -JobName $JobName -Type info -Message "Script start..."

    # Log FTP Variables
    Write-Log -JobName $JobName -Type info -Message "JobName => $JobName"
    Write-Log -JobName $JobName -Type info -Message "FtpServer => $FtpServer"
    Write-Log -JobName $JobName -Type info -Message "FtpFolder => $FtpFolder"
    Write-Log -JobName $JobName -Type info -Message "FtpFile => $FtpFile"
    Write-Log -JobName $JobName -Type info -Message "FTPCredentialPath => $FTPCredentialPath"

    # Log Azure Variables
    Write-Log -JobName $JobName -Type info -Message "AzureStorageAccountName => $AzureStorageAccountName"
    Write-Log -JobName $JobName -Type info -Message "AzureContainerName => $AzureContainerName"
    Write-Log -JobName $JobName -Type info -Message "AzureFileName => $AzureFileName"
    Write-Log -JobName $JobName -Type info -Message "AzureBlobKeyPath => $AzureBlobKeyPath"

    # Log Direction variable
    Write-Log -JobName $JobName -Type info -Message "Direction => $Direction"

    # Log Email variables
    Write-Log -JobName $JobName -Type info -Message "CustomerEmail => $CustomerEmail"
    Write-Log -JobName $JobName -Type info -Message "AdminEmail => $AdminEmail"
    Write-Log -JobName $JobName -Type info -Message "AllEmail => $AllEmail"
    Write-Log -JobName $JobName -Type info -Message "FromEmail => $FromEmail"
    Write-Log -JobName $JobName -Type info -Message "SmtpServer => $SmtpServer"
    Write-Log -JobName $JobName -Type info -Message "SmtpAuthCredentialPath => $SmtpAuthCredentialPath"
    Write-Log -JobName $JobName -Type info -Message "SendSuccessEmail => $SendSuccessEmail"

    # log file retention variables
    Write-Log -JobName $JobName -Type info -Message "KeepFiles => $KeepFiles"
    Write-Log -JobName $JobName -Type info -Message "DeleteFiles => $DeleteFiles"

    # Log Directory variables
    Write-Log -JobName $JobName -Type info -Message "CurrentDirectory => $CurrentDirectory"
    Write-Log -JobName $JobName -Type info -Message "LogDirectory => $LogDirectory"
    Write-Log -JobName $JobName -Type info -Message "TempDirectory => $TempDirectory"
    Write-Log -JobName $JobName -Type info -Message "FtpSessionLogDirectory => $FtpSessionLogDirectory"

    # Log transfer file variable
    Write-Log -JobName $JobName -Type info -Message "TransferLogFile => $TransferLogFile"


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
        "$CurrentDirectory\bin\WinSCP.com",
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
            # Copy-FilesFromFtpToAzureBlob -JobName $JobName -FtpServer $FtpServer -FtpFolder $FtpFolder `
            #     -FtpCredential $FtpCredential -FtpSessionLogDirectory $FtpSessionLogDirectory -TempDirectory $TempDirectory `
            #     -AzureStorageAccountName $AzureStorageAccountName -AzureStorageAccountKey $AzureBlobKey -AzureContainerName $AzureContainerName `
            #     -TransferLogFile $TransferLogFile -CustomerEmail $CustomerEmail -AllEmail $AllEmail -SendSuccessEmail:$SendSuccessEmail `
            #     -DeleteFiles:$DeleteFiles -SmtpServer $SmtpServer -FromEmail $FromEmail -SmtpAuthCredentialPath $SmtpAuthCredentialPath
            Write-Host "1. All Email = $AllEmail"
            Copy-MFFileFromFtpToAzureBlob -JobName $JobName -FtpServer $FtpServer -FtpFolder $FtpFolder -FtpFile $FtpFile `
                -FtpCredential $FtpCredential -FtpSessionLogDirectory $FtpSessionLogDirectory -TempDirectory $TempDirectory `
                -AzureStorageAccountName $AzureStorageAccountName -AzureStorageAccountKey $AzureBlobKey -AzureContainerName $AzureContainerName -AzureFileName $AzureFileName`
                -TransferLogFile $TransferLogFile -CustomerEmail $CustomerEmail -AllEmail $AllEmail -SendSuccessEmail:$SendSuccessEmail `
                -DeleteFiles:$DeleteFiles -SmtpServer $SmtpServer -FromEmail $FromEmail -SmtpAuthCredentialPath $SmtpAuthCredentialPath `
                -WinScpComFile "$CurrentDirectory\bin\WinSCP.com"
        }
        elseif ($Direction -eq "FromAzureBlobToFtp") {
            # Copy-FilesFromAzureBlobToFtp -JobName $JobName -FtpServer $FtpServer -FtpFolder $FtpFolder `
            #     -FtpCredential $FtpCredential -FtpSessionLogDirectory $FtpSessionLogDirectory -TempDirectory $TempDirectory `
            #     -AzureStorageAccountName $AzureStorageAccountName -AzureStorageAccountKey $AzureBlobKey -AzureContainerName $AzureContainerName `
            #     -TransferLogFile $TransferLogFile -CustomerEmail $CustomerEmail -AllEmail $AllEmail -SendSuccessEmail:$SendSuccessEmail `
            #     -DeleteFiles:$DeleteFiles -SmtpServer $SmtpServer -FromEmail $FromEmail -SmtpAuthCredentialPath $SmtpAuthCredentialPath
        }
        else {
            $ErrMsg = "Invalid direction '$Direction'. Exiting."
            Write-Log -JobName $JobName -Type error -Message $ErrMsg
            Send-FailureEmail -JobName $JobName -To $AdminEmail -Message $ErrMsg -SmtpServer $SmtpServer -From $FromEmail -SmtpAuthCredentialPath $SmtpAuthCredentialPath
            Exit
        }
    }
    Catch {
        $Err = $_
        $ErrMsg = "Unhandled exception. Error: $Err"
        Write-Log -JobName $JobName -Type error -Message $ErrMsg
        Send-FailureEmail -JobName $JobName -To $AdminEmail -Message $ErrMsg -SmtpServer $SmtpServer -From $FromEmail -SmtpAuthCredentialPath $SmtpAuthCredentialPath
    }
}
END {
    Write-Log -JobName $JobName -Type info -Message "Script end."
}
