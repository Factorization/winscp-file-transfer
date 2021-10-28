########################
# Variables
########################
# Job Settings
$JobName = "TestAzureToFTP"
$Direction = "FromAzureBlobToFTP"
$KeepFiles = $true

# FTP Settings
$FtpServer = "ftp1-ip.westus2.cloudapp.azure.com"
$FtpFolder = "'PATH.TO.FOLDER.'"
$FtpFile = 'test file.txt'  # "PREFIX" + (Get-Date -Format "MMddyy") + "SUFFIX"
$FtpCredentialPath = 'ftpcred.xml'

# Azure Settings
$AzureStorageAccountName = "jeffazureftp"
$AzureContainerName = "from-auto-hr"
$AzureFileName = $FtpFile
$AzureBlobKeyPath = "azblobkey.xml"

# Email Settings
$CustomerEmail = "jkraemer@ens-inc.com"
$AdminEmail = "jkraemer@ens-inc.com", "jkraemer@ens-inc.com"
$FromEmail = "file_transfer@ens-inc.com"
$SmtpServer = "10.10.10.15"
$SendSuccessEmail = $true
$SmtpAuthCredentialPath = "smtpcred.xml"

Push-Location
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

Pop-Location
