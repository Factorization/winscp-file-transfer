# WinSCP File Transfer Scripts

This repository contains PowerShell scripts to use WinSCP to transfer files an FTP server and Azure blob storage.

## Setup

To use these scripts, you will need to complete the following setup.

1. Install Az.Storage PowerShell module:

    ```PowerShell
    # Open PowerShell as an Administrator
    Install-Module az.storage
    ```

1. Setup FTP credential file:

    ```PowerShell
    # Open Powershell (Ensure you are logged in with the same account that will run the script as a scheduled task)
    # CD to location where script is saved
    $FtpCred = Get-Credential -Message "Enter FTP Username and Password"
    $FtpCred | Export-Clixml .\ftpcred.xml
    ```

1. Setup Azure storage account credential file

    ```PowerShell
    # Open Powershell (Ensure you are logged in with the same account that will run the script as a scheduled task)
    # CD to location where script is saved
    $AzCred = Get-Credential -Message "Enter Azure storage account access key in Password" -Username "None"
    $AzCred | Export-Clixml .\azblobkey.xml
    ```

1. OPTIONALLY: Setup credential file for SMTP authentication for email

    ```PowerShell
    # Open Powershell (Ensure you are logged in with the same account that will run the script as a scheduled task)
    # CD to location where script is saved
    $SmtpCred = Get-Credential -Message "Enter SMTP Auth Username and Password"
    $SmtpCred | Export-Clixml .\smtpcred.xml
    ```

## Using script to copy files from FTP server to Azure blob storage

```PowerShell
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
```

## Using script to copy files from Azure blob storage to FTP server

```PowerShell
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
```
