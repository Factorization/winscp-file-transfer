########################
# Variables
########################
# Job Settings
$JobName = "TestFtpToAzure"
$Direction = "FromFtpToAzureBlob"
$KeepFiles = $true

# FTP Settings
$FtpServer = "ftp1-ip.westus2.cloudapp.azure.com"
$FtpFolder = "'PATH.TO.FOLDER.'"
$FtpFile = 'test file.txt'
$FtpCredentialPath = '.\ftpcred.xml'

# Azure Settings
$AzureStorageAccountName = "jeffazureftp"
$AzureContainerName = "to-auto-hr"
$AzureFileName = $FtpFile
$AzureBlobKeyPath = ".\azblobkey.xml"

# Email Settings
$CustomerEmail = "jeffrey.kraemer@factorization.net"
$AdminEmail = "jeffrey.kraemer@factorization.net", "jeffrey.kraemer@factorization.net"
$FromEmail = "file_transfer@factorization.net"
$SmtpServer = "10.10.10.15"
$SendSuccessEmail = $true
$SmtpAuthCredentialPath = ".\smtpcred.xml"

Set-Location $PSScriptRoot

.\MF_File_Transfer.ps1 -JobName $JobName `
    -FtpServer $FtpServer `
    -FtpFolder $FtpFolder `
    -FtpFile $FtpFile `
    -FtpCredentialPath $FtpCredentialPath `
    -AzureStorageAccountName $AzureStorageAccountName `
    -AzureContainerName $AzureContainerName `
    -AzureFileName $AzureFileName `
    -AzureBlobKeyPath $AzureBlobKeyPath `
    -Direction $Direction `
    -CustomerEmail $CustomerEmail `
    -AdminEmail $AdminEmail `
    -FromEmail $FromEmail `
    -SendSuccessEmail:$SendSuccessEmail `
    -SmtpServer $SmtpServer `
    -KeepFiles:$KeepFiles `
    -SmtpAuthCredentialPath $SmtpAuthCredentialPath
