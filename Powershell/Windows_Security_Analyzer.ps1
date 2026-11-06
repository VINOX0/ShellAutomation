#Requires -Version 5.1

<#
.SYNOPSIS
    Windows Security Analyzer – Automatisierter Sicherheits-Check
.DESCRIPTION
    Dieses Skript analysiert den Sicherheitszustand des lokalen Windows-Systems.
    Es prüft Windows Defender, Firewall, BitLocker, offene Ports und Updates,
    berechnet einen Score (0–10) und speichert das Ergebnis als Log-Datei.
    Pro Tag wird nur einmal ein Bericht geschrieben (F6).

.EXAMPLE
    PS> .\Windows_Security_Analyzer.ps1
    Führt die Sicherheitsanalyse durch und erstellt einen Bericht im Log-Verzeichnis.

.NOTES
    Autor     : Vincent Ozugha
    Version   : 1.1
    Datum     : 08-06-2026
    Anforderungen: F1, F2, F3, F4, F5, F6 | Q1, Q2, Q3 | R1, R2, R3 | T1
    Fremder Code  : Keine
    Ausführung: Als Administrator erforderlich
    Trigger   : Windows-Aufgabenplanung – Jeden Tag um 8:00
#>

# KONFIGURATION 
$LogDir  = "C:\Logs"
$LogFile = "$LogDir\SecurityReport.log"
$Score   = 0
$MaxScore = 10

# FUNKTION: Bericht schreiben
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $Line = "[$Timestamp] [$Level] $Message"
    Add-Content -Path $LogFile -Value $Line -Encoding UTF8
}

# FUNKTION: Score-Einstufung
function Get-ScoreRating {
    param([int]$S)
    if ($S -ge 10) { return "SEHR GUT" } # Das ist sehr Gut
    elseif ($S -ge 8) { return "GUT" }   # Das ist Optimal
    elseif ($S -ge 6) { return "MITTEL" } # Das ist Mittelmäßig
    else { return "KRITISCH" } # Alles darunter ist kritisch, da es unter 5 Punkte liegt
}

# ADMIN-PRÜFUNG 
try {
    $CurrentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $Principal   = New-Object Security.Principal.WindowsPrincipal($CurrentUser)
    if (-not $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Warning "Das Skript muss als Administrator ausgefuehrt werden. Abbruch."
        exit 1
    }
} catch {
    Write-Warning "Fehler bei der Admin-Pruefung: $_"
    exit 1
}

# LOG-ORDNER ERSTELLEN 
try {
    if (-not (Test-Path $LogDir)) {
        New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
    }

    if (-not (Test-Path $LogFile)) {
        New-Item -ItemType File -Path $LogFile -Force | Out-Null
    }
}
catch {
    Write-Warning "Could not create log directory: $_"
    exit 1
}

#Das ist der Header in der File
# HEADER
Add-Content -Path $LogFile -Value "=============================================" -Encoding UTF8
Add-Content -Path $LogFile -Value "  WINDOWS SECURITY ANALYZER - BERICHT        " -Encoding UTF8
Add-Content -Path $LogFile -Value "  Erstellt: $(Get-Date -Format 'dd.MM.yyyy HH:mm:ss')" -Encoding UTF8
Add-Content -Path $LogFile -Value "=============================================" -Encoding UTF8
Add-Content -Path $LogFile -Value "" -Encoding UTF8

# SYSTEMINFORMATIONEN SAMMELN 
Write-Log "=== SYSTEMINFORMATIONEN ===" "INFO"
try {
    $OS       = Get-CimInstance Win32_OperatingSystem
    $Computer = $env:COMPUTERNAME
    $User     = $env:USERNAME

    Write-Log "Computername    : $Computer" "INFO"
    Write-Log "Betriebssystem  : $($OS.Caption) ($($OS.Version))" "INFO"
    Write-Log "Angemeldeter User: $User" "INFO"
    Write-Log "Analysezeitpunkt: $(Get-Date -Format 'dd.MM.yyyy HH:mm:ss')" "INFO"
} catch {
    Write-Log "Fehler beim Lesen der Systeminformationen: $_" "ERROR"
}

Add-Content -Path $LogFile -Value "" -Encoding UTF8
Write-Log "SICHERHEITSPRUEFUNGEN" "INFO"

# SICHERHEITSPRÜFUNGEN MIT SCORE

# Windows Defender Status
try {
    $Defender = Get-MpComputerStatus -ErrorAction Stop
    if ($Defender.AntivirusEnabled -and $Defender.RealTimeProtectionEnabled) {
        Write-Log "Windows Defender : AKTIV (Echtzeit-Schutz ein)" "OK"
        $Score += 2
    } else {
        Write-Log "Windows Defender : INAKTIV oder Echtzeit-Schutz deaktiviert" "WARNUNG"
    }
} catch {
    Write-Log "Windows Defender : Status konnte nicht gelesen werden $_" "ERROR"
}

# Firewall Status alle Profile
try {
    $FWProfiles = Get-NetFirewallProfile -ErrorAction Stop # sorgt dafür, dass Fehler direkt in den catch springen. Get-NetFirewallProfile Domain, Privat, Public
    $AllEnabled = ($FWProfiles | Where-Object { $_.Enabled -eq $false }).Count -eq 0
    if ($AllEnabled) {
        Write-Log "Windows Firewall : AKTIV (alle Profile)" "OK"
        $Score += 2
    } else {
        $Disabled = ($FWProfiles | Where-Object { $_.Enabled -eq $false } | Select-Object -ExpandProperty Name) -join ", "
        Write-Log "Windows Firewall : TEILWEISE INAKTIV (deaktiviert: $Disabled)" "WARNUNG"
    }
} catch {
    Write-Log "Windows Firewall : Status konnte nicht gelesen werden $_" "ERROR"
}

# BitLocker Status
try {
    $BitLocker = Get-BitLockerVolume -MountPoint "C:" -ErrorAction Stop # Get-BitLockerVolume liest den Status von BitLocker für das Laufwerk C:
    if ($BitLocker.ProtectionStatus -eq "On") {       # Wenn Bitlocker.ProtectionStatus "On" ist, dann ist BitLocker aktiviert
        Write-Log "BitLocker (C:)   : AKTIV" "OK"
        $Score += 2
    } else {
        Write-Log "BitLocker (C:)   : INAKTIV (Status: $($BitLocker.ProtectionStatus))" "WARNUNG"
    }
} catch {
    Write-Log "BitLocker        : Nicht verfuegbar oder Fehler $_" "ERROR"
}

#  Offene Ports 
try {
    $CriticalPorts = @(21, 23, 445, 3389, 135, 139) # FTP, Telnet, SMB, RDP, RPC das @ gibt an das es eine Liste ist
    $Listeners     = Get-NetTCPConnection -State Listen -ErrorAction Stop # ErrorAction Stop sorgt dafür, dass Fehler direkt in den catch springen. Get-NetTCPConnection -State Listen liest alle TCP-Verbindungen im Listen-Status
    $OpenPorts     = $Listeners | Select-Object -ExpandProperty LocalPort | Sort-Object -Unique
    $CritFound     = $OpenPorts | Where-Object { $CriticalPorts -contains $_ }

    Write-Log "Offene Ports     : $($OpenPorts -join ', ')" "INFO"

    if ($CritFound.Count -eq 0) {
        Write-Log "Kritische Ports  : Keine kritischen Ports offen" "OK"
        $Score += 2
    } else {
        Write-Log "Kritische Ports  : Kritische Ports gefunden: $($CritFound -join ", ")" "WARNUNG"
    }
} catch {
    Write-Log "Offene Ports     : Fehler beim Lesen $_" "ERROR"
}

# Installierte Sicherheitsupdates
try {
    $Deadline  = (Get-Date).AddDays(-30)
    $Session   = New-Object -ComObject Microsoft.Update.Session
    $Searcher  = $Session.CreateUpdateSearcher()
    $History   = $Searcher.QueryHistory(0, 10)
    $Recent    = @($History | Where-Object { $_.Date -ge $Deadline -and $_.ResultCode -eq 2 }) # 2 bedeutet es war erfolgreich installiert

    if ($Recent.Count -gt 0) {
        Write-Log "Sicherheitsupdates: $($Recent.Count) Update(s) in letzten 30 Tagen installiert" "OK"
        $Score += 2
    } else {
        Write-Log "Sicherheitsupdates: Kein Update in den letzten 30 Tagen installiert" "WARNUNG"
    }
} catch {
    Write-Log "Sicherheitsupdates: Fehler beim Lesen $_" "ERROR"
}

# SCORE AUSGEBEN 
Add-Content -Path $LogFile -Value "" -Encoding UTF8
Write-Log "=== SICHERHEITSBEWERTUNG ===" "INFO"
$Rating = Get-ScoreRating -S $Score
Write-Log "Gesamtscore      : $Score / $MaxScore Punkte" "INFO"
Write-Log "Einstufung       : $Rating" "INFO"

# Einstufung mit Handlungsempfehlung
switch ($Rating) {
    "SEHR GUT"  { Write-Log "Empfehlung       : System ist gut geschuetzt. Regelmaessige Updates empfohlen." "INFO" }
    "GUT"       { Write-Log "Empfehlung       : Kleinere Sicherheitsluecken beheben." "INFO" }
    "MITTEL"    { Write-Log "Empfehlung       : Mehrere Sicherheitsbereiche benoetigen Aufmerksamkeit." "WARNUNG" }
    "KRITISCH"  { Write-Log "Empfehlung       : DRINGEND: Sicherheit des Systems ist gefeahrdet!" "ERROR" }

    default     { Write-Log "Unbekannte Bewertung: $Rating" "ERROR" }
}

# ABSCHLUSS 
Add-Content -Path $LogFile -Value "" -Encoding UTF8
Add-Content -Path $LogFile -Value "=============================================" -Encoding UTF8
Add-Content -Path $LogFile -Value "  Analyse abgeschlossen: $(Get-Date -Format 'dd.MM.yyyy HH:mm:ss')" -Encoding UTF8
Add-Content -Path $LogFile -Value "  Log gespeichert unter: $LogFile" -Encoding UTF8
Add-Content -Path $LogFile -Value "=============================================" -Encoding UTF8

Write-Host "Security Analyzer abgeschlossen. Score: $Score/10 ($Rating)" -ForegroundColor Cyan
Write-Host "Bericht gespeichert: $LogFile" -ForegroundColor Green
