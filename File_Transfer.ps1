<#
 .Synopsis
	A script to transfer files from an FTP server to Azure blob storage or from Azure blob storage to FTP server.

 .Description
	This script uses the WinSCP DLL and the Azure az.storage module to copy files from FTP to Azure blob storage and vice versa.


 .Example
	.\File_Transfer.ps1 -JobName "TestFtpToAzure" `
                    -FtpServer "ftp1-ip.westus2.cloudapp.azure.com" `
                    -FtpFolder "/test2" `
                    -FtpCredentialPath .\ftpcred.xml `
                    -AzureStorageAccountName "jeffazureftp" `
                    -AzureContainerName "to-auto-hr" `
                    -AzureBlobKeyPath .\azblobkey.xml `
                    -Direction "FromFtpToAzureBlob" `
                    -CustomerEmail "jkraemer@ens-inc.com" `
                    -AdminEmail "jkraemer@ens-inc.com" `
                    -SendSuccessEmail:$true `
                    -SmtpServer "10.10.10.15" `
                    -KeepFiles:$false `
                    -FromEmail "file_transfer@ens-inc.com" `
                    -SmtpAuthCredentialPath .\smtpcred.xml

    Copies all the files from the FTP server "ftp1-ip.westus2.cloudapp.azure.com" in folder "/test2" to the Azure storage account "jeffazureftp" in container "to-auto-hr". It will delete the files from the source and send a success email for each file copied.

 .Example
	.\File_Transfer.ps1 -JobName "TestAzureToFtp" `
                    -FtpServer "ftp1-ip.westus2.cloudapp.azure.com" `
                    -FtpFolder "/test1" `
                    -FtpCredentialPath .\ftpcred.xml `
                    -AzureStorageAccountName "jeffazureftp" `
                    -AzureContainerName "from-auto-hr" `
                    -AzureBlobKeyPath .\azblobkey.xml `
                    -Direction "FromAzureBlobToFtp" `
                    -CustomerEmail "jkraemer@ens-inc.com" `
                    -AdminEmail "jkraemer@ens-inc.com" `
                    -SendSuccessEmail:$true `
                    -SmtpServer "10.10.10.15" `
                    -KeepFiles:$false `
                    -FromEmail "file_transfer@ens-inc.com" `
                    -SmtpAuthCredentialPath .\smtpcred.xml

    Copies all the files from the Azure storage account "jeffazureftp" in container "from-auto-hr" to the FTP server "ftp1-ip.westus2.cloudapp.azure.com" in folder "/test1". It will delete the files from the source and send a success email for each file copied.
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

    # FTP Folder path using Unix-style path (no trailing '/')
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
                -DeleteFiles:$DeleteFiles -SmtpServer $SmtpServer -FromEmail $FromEmail -SmtpAuthCredentialPath $SmtpAuthCredentialPath
        }
        elseif ($Direction -eq "FromAzureBlobToFtp") {
            Copy-FilesFromAzureBlobToFtp -JobName $JobName -FtpServer $FtpServer -FtpFolder $FtpFolder `
                -FtpCredential $FtpCredential -FtpSessionLogDirectory $FtpSessionLogDirectory -TempDirectory $TempDirectory `
                -AzureStorageAccountName $AzureStorageAccountName -AzureStorageAccountKey $AzureBlobKey -AzureContainerName $AzureContainerName `
                -TransferLogFile $TransferLogFile -CustomerEmail $CustomerEmail -AllEmail $AllEmail -SendSuccessEmail:$SendSuccessEmail `
                -DeleteFiles:$DeleteFiles -SmtpServer $SmtpServer -FromEmail $FromEmail -SmtpAuthCredentialPath $SmtpAuthCredentialPath
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
}
END {
    Write-Log -JobName $JobName -Type info -Message "Script end."
}
