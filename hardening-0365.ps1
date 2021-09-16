# Securiza Office 365 Enterprise
# Medidas de protección contra ransomware
# Author: J. Vicente Serrano

function isAdmin{
    return [bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")
}

if(-not (isAdmin)){
    Write-Host -ForegroundColor Red "`n [!] You have to run the script like Admin`n"
    return
}

function Get-SIDS{
    $Sids=@{}
    $UserNames = (Get-ChildItem Registry::HKEY_USERS) 2> $null
    foreach($Username in $UserNames){  
        $Identity = $Username.Name | Where {$_ -notlike "*Classes" -and $_ -notlike "*.DEFAULT" -and $_.Length -gt 20}  
        if($Identity){
            $sid = $Identity.Split("\")[1]
            $objSID = New-Object System.Security.Principal.SecurityIdentifier($sid)
            $objUser = $objSID.Translate([System.Security.Principal.NTAccount]).Value.Split("\")[1]
            $Sids[$objUser] = $sid
        }
    }
    return $Sids
}

$Timestamp = Get-Date -Format 'yyyyMMddhhmmss'
$SIDS = Get-SIDS

# Crea directorio de backup del registro antes de la intervención
Write-host -ForegroundColor Green 'Backing up common Office settings'
if(-not (Test-Path C:\BackupOfficeConfig)){
    mkdir C:\BackupOfficeConfig > $nul
}
if(!$?){
    Write-host -ForegroundColor Red '[*] Error creating Backup directory'
    exit
}

# Crea backup de la rama Policies
reg export HKEY_LOCAL_MACHINE\Software\Policies C:\BackupOfficeConfig\$($Timestamp)_policies.reg > $null
if(!$?){
    exit
}

#Politicas de Office en el ámbito de la maquina la máquina
$RegKey = 'HKLM:\Software\Policies\Microsoft\Office'
New-Item -Path $RegKey -Force | Out-Null
$RegKey = 'HKLM:\Software\Policies\Microsoft\Office\16.0'
New-Item -Path $RegKey -Force | Out-Null
$RegKey = 'HKLM:\Software\Policies\Microsoft\Office\16.0\Common'
New-Item -Path $RegKey -Force | Out-Null
# Deshabilita VBA para las aplicaciones de Office 
Set-ItemProperty $RegKey -Name 'VBAOFF' -Value '1' -Force | Out-Null

foreach($key in $SIDS.Keys){
    $key
    $UserName = $key
    $Sid = $SIDS[$UserName]
    $Sid

    $exist = Test-Path -Path "Registry::HKEY_USERS\$Sid"
    if(!$exist){
        Write-Host -ForegroundColor Red "[*] Not Exists Registry::HKEY_USERS\$Sid"
        continue
    }

    $exist = Test-Path -Path "Registry::HKEY_USERS\$Sid\SOFTWARE\Microsoft\Office\16.0\Common\Security"
    if(!$exist){
        Write-Host -ForegroundColor Red "[*] Not Exists Registry::HKEY_USERS\$Sid\SOFTWARE\Microsoft\Office\16.0\Common\Security"
        continue
    }

    # Hacer backups. Si un backup falla no sigue
    Write-host -ForegroundColor Green "Backing up common Office settings on $UserName"
    reg export HKEY_USERS\$SID\Software\Microsoft\Office\Common C:\BackupOfficeConfig\$($Timestamp)_commonsecurity_$UserName.reg > $null
    if(!$?){
        continue
    }

    reg export HKEY_USERS\$SID\Software\Microsoft\Office\16.0\WEF C:\BackupOfficeConfig\$($Timestamp)_commonswef_$UserName.reg > $null
    if(!$?){
        continue
    }
     
    reg export HKEY_USERS\$SID\Software\Microsoft\Office\16.0\word\Security C:\BackupOfficeConfig\$($Timestamp)_wordecurity_$UserName.reg > $null
    if(!$?){
        continue
    }
     
    reg export HKEY_USERS\$SID\Software\Microsoft\Office\16.0\Excel\Security C:\BackupOfficeConfig\$($Timestamp)_excelecurity_$UserName.reg > $null 
    if(!$?){
        continue
    }

    Write-host -ForegroundColor Green "Applying the security patch on $UserName"

    # Comun
    $RegKey = "Registry::HKEY_USERS\$Sid\SOFTWARE\Microsoft\Office\Common\Security"
    New-Item -Path $RegKey -Force | Out-Null
    New-ItemProperty -Path $RegKey -Name 'DisableAllActiveX' -Value '1' -PropertyType DWORD -Force | Out-Null

    ############################################# WORD ##########################################################   
    # Ubicaciones de confianza
    $RegKey = "Registry::HKEY_USERS\$Sid\Software\Microsoft\Office\16.0\word\Security\Trusted Locations"
    # Deshabilita todas las ubicaciones de confianza
    New-ItemProperty -Path $RegKey -Name 'AllLocationsDisabled' -Value '1' -PropertyType DWORD -Force | Out-Null 
    #Permitir localizaciones de red
    New-ItemProperty -Path $RegKey -Name 'allownetworklocations' -Value '0' -PropertyType DWORD -Force | Out-Null
     
    # Documentos de confianza
    $RegKey = "Registry::HKEY_USERS\$Sid\Software\Microsoft\Office\16.0\word\Security\trusted documents"
    # Deshbilitar documentos de confianza de la red interna
    New-ItemProperty -Path $RegKey -Name 'disablenetworktrusteddocuments' -Value '1' -PropertyType DWORD -Force | Out-Null
    # ?
    New-ItemProperty -Path $RegKey -Name 'disableeditfrompv' -Value '1' -PropertyType DWORD -Force | Out-Null
    # Deshabilitar todos documentos de confianza
    New-ItemProperty -Path $RegKey -Name 'DisableTrustedDocuments' -Value '1' -PropertyType DWORD -Force | Out-Null

    # Catalogo de complementos de confianza
    $RegKey = "Registry::HKEY_USERS\$Sid\Software\Microsoft\Office\16.0\WEF\TrustedCatalogs"
    # No permitir que se inicie ningun complemento web
    New-ItemProperty -Path $RegKey -Name 'DisableAllCatalogs' -Value '1' -PropertyType DWORD -Force | Out-Null
    # La proxima vez que se inicie OFfice, borre toda la cache de complementos Web iniciada previamente
    New-ItemProperty -Path $RegKey -Name 'ClearInstalledExtensions' -Value '1' -PropertyType DWORD -Force | Out-Null

    # Habilita la comprobación en archivos de la intranet
    $RegKey = "Registry::HKEY_USERS\$Sid\Software\Microsoft\Office\16.0\word\Security\protectedview"
    New-Item -Path $RegKey -Force | Out-Null
    New-ItemProperty -Path $RegKey -Name 'disableintranetcheck' -Value '0' -PropertyType DWORD -Force | Out-Null

    # Seguridad General
    $RegKey = "Registry::HKEY_USERS\$Sid\Software\Microsoft\Office\16.0\word\Security"
    # Deshabilita todas las macros sin notificación
    New-ItemProperty $RegKey -Name 'VBAWarnings' -Value '4' -Force | Out-Null
    # Habilita la comprobación en archivos de la intranet
    New-ItemProperty -Path $RegKey -Name 'vbadigsigtrustedpublishers' -Value '0' -PropertyType DWORD -Force | Out-Null
    # Bloquear la ejecución desde ficheros que provienen desde internet
    New-ItemProperty -Path $RegKey -Name 'blockcontentexecutionfrominternet' -Value '1' -PropertyType DWORD -Force | Out-Null
    # ?
    New-ItemProperty -Path $RegKey -Name 'vbadigsigtrustedpublishers' -Value '0' -PropertyType DWORD -Force | Out-Null

    # Bloquea ficheros Word 2003
    $RegKey = "Registry::HKEY_USERS\$Sid\Software\Microsoft\Office\16.0\word\Security\fileblock"
    New-Item -Path $RegKey -Force | Out-Null
    New-ItemProperty -Path $RegKey -Name 'word2003files' -Value '3' -PropertyType DWORD -Force | Out-Null
    # Bloquea páginas web
    New-ItemProperty -Path $RegKey -Name 'htmlfiles' -Value '3' -PropertyType DWORD -Force | Out-Null
    # Bloquea ficheros rtf
    New-ItemProperty -Path $RegKey -Name 'rtffiles' -Value '3' -PropertyType DWORD -Force | Out-Null   
    # Bloquea ficheros Word 95
    New-ItemProperty -Path $RegKey -Name 'word95files' -Value '3' -PropertyType DWORD -Force | Out-Null
    # Bloquea ficheros Word 97
    New-ItemProperty -Path $RegKey -Name 'word97files' -Value '3' -PropertyType DWORD -Force | Out-Null
    # Bloquea ficheros Word XML
    New-ItemProperty -Path $RegKey -Name 'wordxmlfiles' -Value '3' -PropertyType DWORD -Force | Out-Null
    # Bloquea ficheros Word 2000
    New-ItemProperty -Path $RegKey -Name 'word2000files' -Value '2' -PropertyType DWORD -Force | Out-Null
    # Bloquea ficheros Word XP
    New-ItemProperty -Path $RegKey -Name 'wordxpfiles' -Value '2' -PropertyType DWORD -Force | Out-Null
    # Bloquea ficheros Word 2003
    New-ItemProperty -Path $RegKey -Name 'word2files' -Value '3' -PropertyType DWORD -Force | Out-Null
    # Bloquea ficheros Word 6.0
    New-ItemProperty -Path $RegKey -Name 'word60files' -Value '3' -PropertyType DWORD -Force | Out-Null
    # Bloquea ficheros Word 2000
    New-ItemProperty -Path $RegKey -Name 'word2000files' -Value '3' -PropertyType DWORD -Force | Out-Null
    # No abrir los archivos seleccionados
    New-ItemProperty -Path $RegKey -Name 'OpenInProtectedView' -Value '0' -PropertyType DWORD -Force | Out-Null

    # Vista Protegida
    $RegKey = "Registry::HKEY_USERS\$Sid\Software\Microsoft\Office\16.0\word\Security\ProtectedView"
    New-Item -Path $RegKey -Force | Out-Null
    New-ItemProperty -Path $RegKey -Name 'DisableInternetFilesInPV' -Value '0' -PropertyType DWORD -Force | Out-Null
    New-ItemProperty -Path $RegKey -Name 'DisableAttachmentsInPV' -Value '0' -PropertyType DWORD -Force | Out-Null
    New-ItemProperty -Path $RegKey -Name 'DisableUnsafeLocationsInPV' -Value '0' -PropertyType DWORD -Force | Out-Null
    New-ItemProperty -Path $RegKey -Name 'EnableForeignTextFileProtectedView' -Value '1' -PropertyType DWORD -Force | Out-Null
    New-ItemProperty -Path $RegKey -Name 'EnableDataBaseFileProtectedView' -Value '1' -PropertyType DWORD -Force | Out-Null
    ############################################################################################################
    
    
    ############################################# EXCEL ##########################################################
    
    # Ubicaciones de confianza
    $RegKey = "Registry::HKEY_USERS\$Sid\Software\Microsoft\Office\16.0\Excel\Security\Trusted Locations"
    #Deshabilita todas las ubicaciones de confianza
    New-ItemProperty -Path $RegKey -Name 'AllLocationsDisabled' -Value '1' -PropertyType DWORD -Force | Out-Null

    # Documentos de confianza
    $RegKey = "Registry::HKEY_USERS\$SID\Software\Microsoft\Office\16.0\excel\Security\Trusted Documents"
    #Deshabilitar todas documentos de confianza
    New-ItemProperty -Path $RegKey -Name 'DisableTrustedDocuments' -Value '1' -PropertyType DWORD -Force | Out-Null

    # Catalogo de complementos de confianza
    $RegKey = "Registry::HKEY_USERS\$Sid\Software\Microsoft\Office\16.0\WEF\TrustedCatalogs"
    # No permitir que se inicie ningun complemento web
    New-ItemProperty -Path $RegKey -Name 'DisableAllCatalogs' -Value '1' -PropertyType DWORD -Force | Out-Null
    # La proxima vez que se inicie Office, borre toda la cache de complementos Web iniciada previamente
    New-ItemProperty -Path $RegKey -Name 'ClearInstalledExtensions' -Value '1' -PropertyType DWORD -Force | Out-Null

    # Configuracion de Macros de VBA
    $RegKey = "Registry::HKEY_USERS\$Sid\Software\Microsoft\Office\16.0\excel\Security"
    # Deshabilitar macros de Excel 4,0 cuando las macros de VBA están habilitadas
    New-ItemProperty -Path $RegKey -Name 'XL4MacroWarningFollowVBA' -Value '0' -PropertyType DWORD -Force | Out-Null
    # Deshbailitar macros sin notificacion
    New-ItemProperty $RegKey -Name 'VBAWarnings' -Value '4' -Force | Out-Null

    # Vista protegida
    $RegKey = "Registry::HKEY_USERS\$Sid\Software\Microsoft\Office\16.0\Excel\Security\ProtectedView"
    New-Item -Path $RegKey -Force | Out-Null
    New-ItemProperty -Path $RegKey -Name 'DisableInternetFilesInPV' -Value '0' -PropertyType DWORD -Force | Out-Null
    New-ItemProperty -Path $RegKey -Name 'DisableAttachmentsInPV' -Value '0' -PropertyType DWORD -Force | Out-Null
    New-ItemProperty -Path $RegKey -Name 'DisableUnsafeLocationsInPV' -Value '0' -PropertyType DWORD -Force | Out-Null
    New-ItemProperty -Path $RegKey -Name 'EnableForeignTextFileProtectedView' -Value '1' -PropertyType DWORD -Force | Out-Null
    New-ItemProperty -Path $RegKey -Name 'EnableDataBaseFileProtectedView' -Value '1' -PropertyType DWORD -Force | Out-Null

    # Barra de mensajes
    $RegKey = "Registry::HKEY_USERS\$Sid\Software\Microsoft\Office\16.0\Common\TrustCenter"
    # (Quita la barra con el boton "Habilitar macros")
    New-ItemProperty -Path $RegKey -Name 'TrustBar' -Value '1' -PropertyType DWORD -Force | Out-Null
    
    # Contenido externo
    $RegKey = "Registry::HKEY_USERS\$Sid\Software\Microsoft\Office\16.0\Excel\Security"
    # Preguntar al usuarios sobre las conexiones de datos
    New-ItemProperty -Path $RegKey -Name 'DataConnectionWarnings' -Value '1' -PropertyType DWORD -Force | Out-Null
    # Preguntar al usuario sobre la actualizaciones automatica de los vinculos de libro
    New-ItemProperty -Path $RegKey -Name 'WorkbookLinkWarnings' -Value '1' -PropertyType DWORD -Force | Out-Null
    # Preguntar al usuario sobre los tipos de datos vinculados
    New-ItemProperty -Path $RegKey -Name 'RichDataConnectionWarnings' -Value '1' -PropertyType DWORD -Force | Out-Null
    # Deshabilitar la busqueda de datos dinamicos de Exchange Server
    New-ItemProperty -Path $RegKey -Name 'DisableDDEServerLookup' -Value '1' -PropertyType DWORD -Force | Out-Null

    # Configuración de bloqueo de archivos
    $RegKey = "Registry::HKEY_USERS\$Sid\Software\Microsoft\Office\16.0\excel\Security\FileBlock"
    New-Item -Path $RegKey -Force | Out-Null
    New-ItemProperty -Path $RegKey -Name 'HtmlandXmlssFiles' -Value '2' -PropertyType DWORD -Force | Out-Null
    New-ItemProperty -Path $RegKey -Name 'XL9597WorkbooksandTemplates' -Value '2' -PropertyType DWORD -Force | Out-Null
    New-ItemProperty -Path $RegKey -Name 'XL95Workbooks' -Value '2' -PropertyType DWORD -Force | Out-Null
    New-ItemProperty -Path $RegKey -Name 'XL97AddIns' -Value '2' -PropertyType DWORD -Force | Out-Null
    New-ItemProperty -Path $RegKey -Name 'XL97WorkbooksandTemplates' -Value '2' -PropertyType DWORD -Force | Out-Null
    New-ItemProperty -Path $RegKey -Name 'DifandSylkFiles' -Value '2' -PropertyType DWORD -Force | Out-Null
    New-ItemProperty -Path $RegKey -Name 'DBaseFiles' -Value '2' -PropertyType DWORD -Force | Out-Null
    New-ItemProperty -Path $RegKey -Name 'HtmlandXmlssFiles' -Value '2' -PropertyType DWORD -Force | Out-Null
    New-ItemProperty -Path $RegKey -Name 'OfflineCubeFiles' -Value '2' -PropertyType DWORD -Force | Out-Null
    New-ItemProperty -Path $RegKey -Name 'XllFiles' -Value '2' -PropertyType DWORD -Force | Out-Null
    New-ItemProperty -Path $RegKey -Name 'OpenInProtectedView' -Value '0' -PropertyType DWORD -Force | Out-Null   

    # Inicio de sesión basado en formularios
    $RegKey = "Registry::HKEY_USERS\$Sid\Software\Microsoft\Office\16.0\Common\Identity"
    New-ItemProperty -Path $RegKey -Name 'TCSettingBlockFBAPrompts' -Value '1' -PropertyType DWORD -Force | Out-Null 

    Write-Host -ForegroundColor Green "Word and Excel have been patched in $UserName"
}
