<#
.SYNOPSIS
    LIGHT VERSION (5 of 21 checks, free). DNS and DHCP report: checks the Windows DNS servers and DHCP servers of a domain and generates an
    HTML report about aging, stale entries, insecure zones, forwarders, DHCP scope utilization, fault tolerance, and options.

    Deutsch:
    LIGHT-VERSION (5 von 21 Prüfpunkten, kostenlos). DNS- und DHCP-Bericht: prüft die Windows-DNS-Server und DHCP-Server einer Domäne und erzeugt einen
    HTML-Bericht zu Alterung, veralteten Einträgen, unsicheren Zonen, Weiterleitungen, Auslastung der
    DHCP-Bereiche, Ausfallschutz und Optionen.

.DESCRIPTION
    The script operates exclusively READ-ONLY. It does not change zones, entries, scopes, or settings,
    deletes nothing, and transfers no data. It writes exactly one HTML file (and CSV files if desired)
    to the specified output folder.

    Prerequisites: Windows PowerShell 5.1, the modules "ActiveDirectory", "DnsServer", and "DhcpServer"
    (present on servers with the respective role, otherwise RSAT) and an account that is allowed to manage the DNS and DHCP servers
    (e.g., domain admin). Anything that cannot be queried appears in the report as a finding -
    it is never silently treated as "OK".

    Deutsch:
    Das Skript arbeitet ausschließlich LESEND. Es ändert keine Zonen, Einträge, Bereiche oder Einstellungen,
    löscht nichts und überträgt keine Daten. Es schreibt genau eine HTML-Datei (und auf Wunsch CSV-Dateien)
    in den angegebenen Ausgabeordner.

    Voraussetzungen: Windows PowerShell 5.1, die Module "ActiveDirectory", "DnsServer" und "DhcpServer"
    (auf Servern mit der jeweiligen Rolle vorhanden, sonst RSAT) und ein Konto, das die DNS- und DHCP-Server
    verwalten darf (z. B. Domänen-Admin). Was sich nicht abfragen lässt, erscheint im Bericht als Befund -
    es wird nie stillschweigend als "in Ordnung" gewertet.

.PARAMETER Ausgabe
    Path to the HTML file. Default: DNS-DHCP-Bericht_<Domäne>_<Datum>.html in the current folder.

    Deutsch:
    Pfad der HTML-Datei. Standard: DNS-DHCP-Bericht_<Domäne>_<Datum>.html im aktuellen Ordner.

.PARAMETER DnsServer
    DNS servers to be checked. Default: all name servers in the domain zone.

    Deutsch:
    DNS-Server, die geprüft werden. Standard: alle Namenserver der Domänenzone.

.PARAMETER DhcpServer
    DHCP servers to be checked. Default: all DHCP servers authorized in Active Directory.

    Deutsch:
    DHCP-Server, die geprüft werden. Standard: alle im Active Directory autorisierten DHCP-Server.

.PARAMETER VeraltetTage
    Dynamic DNS entries that have not been updated for longer than this are considered stale (default 60).

    Deutsch:
    Dynamische DNS-Einträge, die länger nicht aktualisiert wurden, gelten als veraltet (Standard 60).

.PARAMETER AuslastungProzent
    DHCP scopes at or above this utilization are reported (default 80).

    Deutsch:
    DHCP-Bereiche ab dieser Auslastung werden gemeldet (Standard 80).

.PARAMETER OhneDns
    Skips the DNS part.

    Deutsch:
    Überspringt den DNS-Teil.

.PARAMETER OhneDhcp
    Skips the DHCP part.

    Deutsch:
    Überspringt den DHCP-Teil.

.PARAMETER Csv
    In addition, writes a CSV file next to the report for each checkpoint with hits.

    Deutsch:
    Schreibt zusätzlich je Prüfpunkt mit Treffern eine CSV-Datei neben den Bericht.

.PARAMETER NichtOeffnen
    Does not automatically open the finished report in the browser.

    Deutsch:
    Öffnet den fertigen Bericht nicht automatisch im Browser.

.PARAMETER PassThru
    Additionally returns the findings as objects (for custom evaluations or scheduled tasks).

    Deutsch:
    Gibt die Befunde zusätzlich als Objekte zurück (für eigene Auswertungen oder geplante Aufgaben).

.PARAMETER Language
    Language of the report and the console output: 'de' (German) or 'en' (English). Default: German if the Windows display language
    is German, otherwise English.

    Deutsch:
    Sprache von Bericht und Konsolenausgabe: 'de' (Deutsch) oder 'en' (Englisch). Standard: Deutsch, wenn die Anzeigesprache von
    Windows Deutsch ist, sonst Englisch.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\DNS-DHCP-Bericht.ps1

.EXAMPLE
    .\DNS-DHCP-Bericht.ps1 -DhcpServer dhcp01 -AuslastungProzent 70 -Csv

.NOTES
    IT Admin Tools by MM - Version 1.0 (10.2026)
    Kein Ersatz für eine Überwachung oder Sicherheitsprüfung. Nutzung auf eigene Verantwortung.
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateSet('de', 'en')][string]$Language = $(if ((Get-UICulture).TwoLetterISOLanguageName -eq 'de') { 'de' } else { 'en' }),
    [Alias('Output')][string]$Ausgabe,
    [string[]]$DnsServer,
    [string[]]$DhcpServer,
    [ValidateRange(1, 3650)][int]$VeraltetTage = 60,
    [ValidateRange(1, 100)][int]$AuslastungProzent = 80,
    [switch]$OhneDns,
    [switch]$OhneDhcp,
    [switch]$Csv,
    [Alias('NoOpen')][switch]$NichtOeffnen,
    [switch]$PassThru
)
# Sprache des Berichts: de oder en (Parameter -Language). T 'deutsch' 'english' liefert den Text der gewählten Sprache.
$En = ($Language -eq 'en')
function T([string]$de, [string]$en) { if ($script:En) { $en } else { $de } }

$ErrorActionPreference = 'Stop'
$Version = '1.1'

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Host (T 'Das PowerShell-Modul "ActiveDirectory" fehlt.' 'The PowerShell module "ActiveDirectory" is missing.') -ForegroundColor Red
    Write-Host 'Windows Server:  Install-WindowsFeature RSAT-AD-PowerShell, RSAT-DNS-Server, RSAT-DHCP'
    exit 2
}
Import-Module ActiveDirectory

#@SPRACHE@
# ------------------------------------------------------------------ Hilfsfunktionen
function Datum($d, $leer = $null) { if ($null -eq $leer) { $leer = T 'nie' 'never' }; if ($d) { ([datetime]$d).ToString((T 'dd.MM.yyyy' 'yyyy-MM-dd')) } else { $leer } }
function JaNein($b) { if ($b) { T 'Ja' 'Yes' } else { T 'Nein' 'No' } }
function Ort($dn) { ($dn -replace '^(CN|OU)=.+?(?<!\\),', '') -replace ',DC=.*$', '' }
function Html($t) { [System.Net.WebUtility]::HtmlEncode([string]$t) }
function Kurz($t, $n = 220) { $t = ([string]$t -replace '\s+', ' ').Trim(); if ($t.Length -gt $n) { $t.Substring(0, $n) + ' ...' } else { $t } }

# CSV-Dateien öffnen sich in Excel: Werte, die mit = + - @ beginnen, würden dort als Formel ausgeführt (Namen von Dateien, Ordnern, Konten oder Computern
# stammen von Benutzern). Diese Funktion ersetzt für dieses Skript den Befehl Export-Csv und setzt vor solche Werte ein Hochkomma.
function Export-Csv {
    [CmdletBinding()]
    param([Parameter(ValueFromPipeline = $true)]$InputObject, [Parameter(Mandatory)][string]$Path, [switch]$NoTypeInformation, [string]$Delimiter = ';', [string]$Encoding = 'UTF8')
    begin { $alle = New-Object System.Collections.Generic.List[object] }
    process { if ($null -ne $InputObject) { $alle.Add($InputObject) } }
    end {
        $sicher = foreach ($o in $alle) {
            $n = [ordered]@{}
            foreach ($p in $o.PSObject.Properties) { $v = $p.Value; if (($v -is [string]) -and ($v -match '^[=+@\t\r]|^-.')) { $v = "'" + $v }; $n[$p.Name] = $v }
            [pscustomobject]$n
        }
        if ($alle.Count) { $sicher | Microsoft.PowerShell.Utility\Export-Csv -Path $Path -NoTypeInformation:$NoTypeInformation -Delimiter $Delimiter -Encoding $Encoding }   # leere Liste: keine Datei (sie hätte keine Kopfzeile)
    }
}

# Tabellen: ConvertTo-Html und Export-Csv nehmen die Spalten des ersten Objekts. Haben die Zeilen einer Liste verschiedene
# Eigenschaften (z. B. Fehlzeile neben normalen Treffern), gingen Spalten verloren: alle Namen der Reihe nach vereinigen.
function Einheitlich($liste) {
    $liste = @($liste | Where-Object { $null -ne $_ })
    if ($liste.Count -ge 2) {
        $namen = New-Object System.Collections.Generic.List[string]
        foreach ($o in $liste) { foreach ($p in $o.PSObject.Properties.Name) { if (-not $namen.Contains($p)) { $namen.Add($p) } } }
        if ($namen.Count -ne @($liste[0].PSObject.Properties.Name).Count) { $liste = @($liste | Select-Object -Property $namen) }
    }
    SpaltenAnzeige $liste
}
# Englische Berichte: Spaltenüberschriften aus der Übersetzungstabelle (intern bleiben die deutschen Namen, der Code liest sie weiter)
$SpaltenEn = @{
    'Abfrage' = 'Query'
    'Administrator' = 'Administrator'
    'Adresse' = 'Address'
    'Aktiv' = 'Active'
    'Aktiv verknüpft mit' = 'Active linked to'
    'Aktive Verknüpfungen' = 'Active links'
    'Alter in Tagen' = 'Age in days'
    'Angelegt' = 'Created'
    'Anmeldung' = 'Last logon'
    'Anmeldungen' = 'Logons'
    'Anteil (%)' = 'Share (%)'
    'Anzahl' = 'Count'
    'Art' = 'Account type'
    'Auf Domänencontroller' = 'On domain controller'
    'Aufräumen' = 'Cleanup'
    'Auslastung' = 'Utilization'
    'Auslösender Rechner' = 'Triggering computer'
    'Auslösender Rechner (Anzahl)' = 'Triggering computers (count)'
    'Aussteller' = 'Issuer'
    'Beispiele' = 'Examples'
    'Belegt' = 'Used'
    'Belegt (%)' = 'Used (%)'
    'Benutzer und Computer (auch verschachtelt)' = 'Users and computers (also nested)'
    'Benutzereinstellungen' = 'User settings'
    'Benutzername' = 'Username'
    'Berechtigter' = 'Principal'
    'Bereich' = 'Scope'
    'Bereiche' = 'Scopes'
    'Beschreibung' = 'Description'
    'Besitzer' = 'Owner'
    'Betriebssystem' = 'OS'
    'Betroffene Konten' = 'Affected accounts'
    'Bewertung' = 'Rating'
    'Bis' = 'To'
    'BitLocker' = 'BitLocker'
    'Computer' = 'Computer'
    'Computereinstellungen' = 'Computer settings'
    'Darf anwenden' = 'Can apply'
    'Darf delegieren an' = 'Can delegate to'
    'Darf sich hier als Benutzer ausgeben' = 'Can log on as user'
    'Datei' = 'File'
    'Dateien' = 'Files'
    'Dateisystem' = 'File system'
    'Dateityp' = 'File type'
    'Datenbank' = 'Database'
    'Detail' = 'Detail'
    'Details' = 'Details'
    'Direkte Mitglieder' = 'Direct members'
    'Domäne' = 'Domain'
    'Domänencontroller' = 'Domain controller'
    'Domänennamenmaster' = 'Domain naming master'
    'Dynamische Updates' = 'Dynamic updates'
    'E-Mail' = 'Email'
    'Eigenschaft' = 'Property'
    'Einstellung' = 'Setting'
    'Empfohlen' = 'Recommended'
    'Enthaltene Gruppen' = 'Included groups'
    'Ereignisse' = 'Events'
    'Erreichbar' = 'Reachable'
    'Erste' = 'First'
    'Erster' = 'First'
    'Erzwungen' = 'Forced'
    'Failover' = 'Failover'
    'Falsches Kennwort' = 'Wrong password'
    'Fehlanmeldungen am DC' = 'Failed logons at DC'
    'Fehlversuche' = 'Failed attempts'
    'Feststellung' = 'Finding'
    'Fingerabdruck' = 'Fingerprint'
    'Firewall' = 'Firewall'
    'Frei' = 'Free'
    'Freigabe' = 'Share'
    'Freigaberecht' = 'Share permission'
    'Funktion' = 'Function'
    'Gelesen von' = 'Read by'
    'Geprüft' = 'Checked'
    'Gesamtgröße' = 'Total size'
    'Geschützte Benutzer' = 'Protected users'
    'Gesperrt seit' = 'Locked since'
    'Geändert' = 'Changed'
    'Gilt' = 'Applies to'
    'Gilt für' = 'Applies to'
    'Globaler Katalog' = 'Global catalog'
    'Grenze' = 'Limit'
    'Groesse' = 'Size'
    'Grund' = 'Reason'
    'Gruppe' = 'Group'
    'Gruppen' = 'Groups'
    'Gruppen (auch verschachtelt)' = 'Groups (including nested)'
    'Gruppenrichtlinie' = 'Group policy'
    'Größe' = 'Size'
    'Größe (GB)' = 'Size (GB)'
    'Gültig ab' = 'Valid from'
    'Gültig bis' = 'Valid to'
    'Herkunft' = 'Origin'
    'Hersteller' = 'Vendor'
    'Hinweis' = 'Note'
    'Häufigster Grund' = 'Most common reason'
    'IP-Adresse' = 'IP address'
    'Im AD gespeichert' = 'Stored in AD'
    'In der Domäne vorhanden' = 'Present in domain'
    'Infrastrukturmaster' = 'Infrastructure master'
    'Inhalt' = 'Content'
    'Ist' = 'Is'
    'Kennung' = 'ID'
    'Kennwort gesetzt' = 'Password set'
    'Kennwort läuft nie ab' = 'Password never expires'
    'Kerberos' = 'Kerberos'
    'Konten' = 'Accounts'
    'Konten (auch verschachtelt)' = 'Accounts (also nested)'
    'Konto' = 'Account'
    'Konto für DNS-Einträge' = 'Account for DNS entries'
    'Kopie bleibt im Postfach' = 'Copy remains in mailbox'
    'LAPS' = 'LAPS'
    'LAPS-Ablauf' = 'LAPS expiry'
    'Laufwerk' = 'Drive'
    'Lease-Dauer' = 'Lease duration'
    'Leitet weiter an' = 'Forwards to'
    'Leseweg' = 'Read path'
    'Letzte Aktualisierung' = 'Last update'
    'Letzte Anmeldung' = 'Last logon'
    'Letzte Vollsicherung' = 'Last full backup'
    'Letzte inkrementelle Sicherung' = 'Last incremental backup'
    'Letzter' = 'Last'
    'Letzter Aufräumlauf' = 'Last cleanup run'
    'Letzter Start' = 'Last start'
    'Lokale Admins' = 'Local admins'
    'Mindestlänge' = 'Minimum length'
    'Mitglied' = 'Member'
    'Mitglieder' = 'Members'
    'NLA' = 'NLA'
    'NTLM' = 'NTLM'
    'Name' = 'Name'
    'Nr.' = 'No.'
    'Objekt' = 'Object'
    'Ordner' = 'Folder'
    'Organisationseinheit' = 'OU'
    'Ort' = 'Location'
    'PDC-Emulator' = 'PDC emulator'
    'Pfad' = 'Path'
    'Postfach' = 'Mailbox'
    'Postfach-Typ' = 'Mailbox type'
    'Postfachtyp' = 'Mailbox type'
    'Postfächer' = 'Mailboxes'
    'Privilegierte Gruppen' = 'Privileged groups'
    'Programm' = 'Program'
    'Prüfpunkt' = 'Checkpoint'
    'Quelle' = 'Source'
    'Quelle (Anzahl)' = 'Sources (count)'
    'RID-Master' = 'RID master'
    'Recht' = 'Permission'
    'Rechte' = 'Permissions'
    'Regel' = 'Rule'
    'Reihenfolge' = 'Order'
    'SPN' = 'SPN'
    'Schemamaster' = 'Schema master'
    'Schlüssel' = 'Key'
    'Schreibgeschützt' = 'Read-only'
    'Sendesperre ab' = 'Send blocked from'
    'Server' = 'Server'
    'Sid' = 'SID'
    'Signatur' = 'Signature'
    'Speicher' = 'Storage'
    'Sperrungen' = 'Lockouts'
    'Stand' = 'Status'
    'Standort' = 'Site'
    'Status' = 'Status'
    'Support-Ende' = 'End of support'
    'Support-Ende (spätestes)' = 'End of support (latest)'
    'Tage bis Ablauf' = 'Days until expiry'
    'Tage her' = 'Days ago'
    'Tage ohne Anmeldung' = 'Days without logon'
    'Tage seit Ablauf' = 'Days since expiry'
    'Treffer' = 'Hits'
    'Typ' = 'Type'
    'Vererbung' = 'Inheritance'
    'Verschiedene Konten' = 'Distinct accounts'
    'Verschlüsselt' = 'Encrypted'
    'Version' = 'Version'
    'Version C/B' = 'Version C/B'
    'Verweigert für' = 'Denied for'
    'Verwendung' = 'Use'
    'Virenschutz' = 'Antivirus'
    'Von' = 'From'
    'WMI-Filter' = 'WMI filter'
    'Weg' = 'Path'
    'Weiterleitungen' = 'Forwarding'
    'Wert' = 'Value'
    'Wirksame Richtlinie' = 'Effective policy'
    'Wirksames Recht' = 'Effective permission'
    'Wirkung' = 'Effect'
    'Zeit' = 'Time'
    'Zeitpunkt' = 'Time'
    'Zeitraum' = 'Period'
    'Zertifikat' = 'Certificate'
    'Zone' = 'Zone'
    'Zonen' = 'Zones'
    'Zonenübertragung' = 'Zone transfer'
    'Zugriff für große Gruppen' = 'Access for large groups'
    'Zugriffsbasierte Aufzählung' = 'Access-based enumeration'
    'Zuletzt' = 'Last'
    'Zustand' = 'State'
    'davon Größe (GB)' = 'Of which size (GB)'
    'davon aktiv' = 'Of which active'
    'davon inaktiv' = 'Of which inactive'
    'davon unbekannte Konten' = 'Of which unknown accounts'
    'ist Mitglied von' = 'Member of'
    'Älter als 5 Jahre' = 'Older than 5 years'
    'Älter als 5 Jahren' = 'Older than 5 years'
    'Ältester Eintrag' = 'Oldest entry'
    'Über' = 'Via'
    'Überwachungsprotokoll' = 'Audit log'
}
# Werte, die der Code intern auf Deutsch vergleicht (z. B. Art = 'Benutzer'), erscheinen im englischen Bericht übersetzt (nur Anzeige und CSV)
$WerteEn = New-Object System.Collections.Specialized.OrderedDictionary([System.StringComparer]::Ordinal)   # Groß-/Kleinschreibung zählt (Verwaist / verwaist)
$WerteEn.Add('Alle erweiterten Rechte (u. a. Kennwort zurücksetzen)', 'All extended rights (including password reset)')
$WerteEn.Add('Kein Serverbetriebssystem (Support nicht bewertet)', 'No server operating system (support not assessed)')
$WerteEn.Add('Rechte je Ordner (nur dort, wo sie gesetzt werden)', 'Permissions per folder (only where set)')
$WerteEn.Add('Mehrfach freigegebene Ordner (nur einmal gezählt)', 'Folders shared multiple times (counted only once)')
$WerteEn.Add('Übersprungene Verknüpfungen (Junctions/Symlinks)', 'Skipped links (Junctions/Symlinks)')
$WerteEn.Add('Der Ordner der Freigabe existiert nicht mehr.', 'The share folder no longer exists.')
$WerteEn.Add('DHCP-Überwachungsprotokoll ist ausgeschaltet', 'DHCP audit log is disabled')
$WerteEn.Add('Vollzugriff und "Senden als" im Überblick', 'Full access and "Send as" overview')
$WerteEn.Add('Ordner der Freigabe existiert nicht mehr', 'Share folder no longer exists')
$WerteEn.Add('Enthält außer Sicherheitseinstellungen:', 'Contains except security settings:')
$WerteEn.Add('Nicht geprüft - Postfach nicht gefunden', 'Not checked - mailbox not found')
$WerteEn.Add('WMI-Filter nicht lesbar - nicht geprüft', 'WMI filter not readable - not checked')
$WerteEn.Add('Abfrage fehlgeschlagen - nicht geprüft', 'Query failed - not checked')
$WerteEn.Add('Nicht im Active Directory gespeichert', 'Not stored in Active Directory')
$WerteEn.Add('keine im Active Directory autorisiert', 'None authorized in Active Directory')
$WerteEn.Add('Zugriff auf den Ordner nicht möglich', 'Access to folder not possible')
$WerteEn.Add('Zertifikate (öffentliche Schlüssel)', 'Certificates (public keys)')
$WerteEn.Add('Domänencontroller der Organisation', 'Organization domain controllers')
$WerteEn.Add('Remotedesktop erlaubt Verbindungen', 'Remote Desktop allows connections')
$WerteEn.Add('autorisierte DHCP-Server ermitteln', 'Determine authorized DHCP servers')
$WerteEn.Add('Windows Server 2008 R2 und älter', 'Windows Server 2008 R2 and older')
$WerteEn.Add('Konto deaktiviert oder gesperrt', 'Account disabled or locked')
$WerteEn.Add('Vollzugriff (Zusatz: ObjectType', 'Full access (additional: ObjectType')
$WerteEn.Add('Kennwort oder Konto abgelaufen', 'Password or account expired')
$WerteEn.Add('Lokale Administratorengruppen', 'Local administrator groups')
$WerteEn.Add('Berechtigungen/Besitz ändern', 'Change permissions/ownership')
$WerteEn.Add('Freigabepfade nicht sichtbar', 'Share paths not visible')
$WerteEn.Add('Aktive privilegierte Konten', 'Active privileged accounts')
$WerteEn.Add('Gruppe hat keine Mitglieder', 'Group has no members')
$WerteEn.Add('Keine Verbindung zum Server', 'No connection to server')
$WerteEn.Add('unerlaubte Zeichen im Namen', 'Illegal characters in name')
$WerteEn.Add('Geprüfte Domänencontroller', 'Checked domain controllers')
$WerteEn.Add('Authentifizierte Benutzer', 'Authenticated Users')
$WerteEn.Add('Schwellen dieses Berichts', 'Thresholds of this report')
$WerteEn.Add('Benutzer (inetOrgPerson)', 'User (inetOrgPerson)')
$WerteEn.Add('Datenbestand je Freigabe', 'Data inventory per share')
$WerteEn.Add('Kontosperrungsrichtlinie', 'Account lockout policy')
$WerteEn.Add('Sicherheitseinstellungen', 'Security settings')
$WerteEn.Add('Alle erweiterten Rechte', 'All extended rights')
$WerteEn.Add('Hinweise zur Auswertung', 'Notes for evaluation')
$WerteEn.Add('Nicht abgefragte Server', 'Servers not queried')
$WerteEn.Add('Unterordner und Dateien', 'Subfolders and files')
$WerteEn.Add('Bestätigtes Schreiben:', 'Validated write:')
$WerteEn.Add('Installierte Programme', 'Installed programs')
$WerteEn.Add('Konto für DNS-Einträge', 'Account for DNS records')
$WerteEn.Add('Kontosperrungsschwelle', 'Account lockout threshold')
$WerteEn.Add('Nicht lesbare Bereiche', 'Unreadable areas')
$WerteEn.Add('Berechtigungen ändern', 'Change permissions')
$WerteEn.Add('Hinweise zum Auslesen', 'Notes for reading')
$WerteEn.Add('Windows 8.1 und älter', 'Windows 8.1 and older')
$WerteEn.Add('Überwachungsprotokoll', 'Audit log')
$WerteEn.Add('Nicht berücksichtigt', 'Not considered')
$WerteEn.Add('Anonymous-Anmeldung', 'Anonymous logon')
$WerteEn.Add('Infrastrukturmaster', 'Infrastructure master')
$WerteEn.Add('Secure Boot ist aus', 'Secure Boot is off')
$WerteEn.Add('Domänennamenmaster', 'Domain naming master')
$WerteEn.Add('Kennwortrichtlinie', 'Password policy')
$WerteEn.Add('Komponentenwartung', 'Component servicing')
$WerteEn.Add('alle Eigenschaften', 'all properties')
$WerteEn.Add('Besitz übernehmen', 'Take ownership')
$WerteEn.Add('Domänencontroller', 'Domain Controllers')
$WerteEn.Add('Falsches Kennwort', 'Incorrect password')
$WerteEn.Add('Konten-Operatoren', 'Account Operators')
$WerteEn.Add('Nur dieser Ordner', 'Only this folder')
$WerteEn.Add('Domänen-Benutzer', 'Domain Users')
$WerteEn.Add('Format unbekannt', 'Format unknown')
$WerteEn.Add('Sonstige Dateien', 'Other files')
$WerteEn.Add('Ältester Eintrag', 'Oldest entry')
$WerteEn.Add('Domänencomputer', 'Domain Computers')
$WerteEn.Add('Konto unbekannt', 'Account unknown')
$WerteEn.Add('Standard (alle)', 'Default (all)')
$WerteEn.Add('Computerkonten', 'Computer accounts')
$WerteEn.Add('Konto gesperrt', 'Account locked')
$WerteEn.Add('Nicht erreicht', 'Not reached')
$WerteEn.Add('DHCP-Bereiche', 'DHCP scopes')
$WerteEn.Add('Dieser Ordner', 'This folder')
$WerteEn.Add('Gruppe/System', 'Group/system')
$WerteEn.Add('Remotedesktop', 'Remote Desktop')
$WerteEn.Add('Arbeitsplatz', 'Workstation')
$WerteEn.Add('Schemamaster', 'Schema master')
$WerteEn.Add('DHCP-Server', 'DHCP server')
$WerteEn.Add('Datenbanken', 'Databases')
$WerteEn.Add('Sonderkonto', 'Special account')
$WerteEn.Add('Unterordner', 'Subfolders')
$WerteEn.Add('Vollzugriff', 'Full control')
$WerteEn.Add('Zugriff von', 'Access from')
$WerteEn.Add('DNS-Server', 'DNS server')
$WerteEn.Add('Inaktiv ab', 'Inactive from')
$WerteEn.Add('Schreiben:', 'Write:')
$WerteEn.Add('Verweigern', 'Deny')
$WerteEn.Add('DNS-Zonen', 'DNS zones')
$WerteEn.Add('Schreiben', 'Write')
$WerteEn.Add('Sonstiges', 'Other')
$WerteEn.Add('Standorte', 'Sites')
$WerteEn.Add('Unbekannt', 'Unknown')
$WerteEn.Add('unbekannt', 'unknown')
$WerteEn.Add('(Wurzel)', '(root)')
$WerteEn.Add('Anlegen:', 'Create:')
$WerteEn.Add('Benutzer', 'User')
$WerteEn.Add('Erlauben', 'Allow')
$WerteEn.Add('Netzwerk', 'Network')
$WerteEn.Add('Verwaist', 'Orphaned')
$WerteEn.Add('verwaist', 'orphaned')
$WerteEn.Add('Dateien', 'Files')
$WerteEn.Add('Gruppen', 'Groups')
$WerteEn.Add('Anonym', 'Anonymous')
$WerteEn.Add('Domäne', 'Domain')
$WerteEn.Add('Gruppe', 'Group')
$WerteEn.Add('Umfang', 'Scope')
$WerteEn.Add('direkt', 'direct')
$WerteEn.Add('Ändern', 'Change')
$WerteEn.Add('Lesen', 'Read')
$WerteEn.Add('über', 'via')
$WerteMuster = @()
foreach ($k in ($WerteEn.Keys | Sort-Object Length -Descending)) { $WerteMuster += , @([regex]::new('(?<![\p{L}\d])' + [regex]::Escape($k) + '(?![\p{L}\d])'), $WerteEn[$k]) }
function WertAnzeige($v) {
    if (-not $script:En -or $v -isnot [string] -or -not $v) { return $v }
    if ($v.Contains('\')) { return $v }   # Kontonamen (DOMÄNE\Name) und Pfade bleiben, wie sie sind
    foreach ($m in $WerteMuster) { $v = $m[0].Replace($v, $m[1]) }
    $v
}
function SpaltenAnzeige($liste) {
    if (-not $script:En -or -not @($liste).Count) { return $liste }
    foreach ($o in @($liste)) {
        $n = [ordered]@{}
        foreach ($p in $o.PSObject.Properties) { $k = $p.Name; if ($SpaltenEn.ContainsKey($k)) { $k = $SpaltenEn[$k] }; $i = 2; $k0 = $k; while ($n.Contains($k)) { $k = "$k0 $i"; $i++ }; $n[$k] = WertAnzeige $p.Value }
        [pscustomobject]$n
    }
}
# Sortierschluessel fuer Nummern wie K2, K10: erst Buchstaben, dann die Zahl als Zahl
function IdZahl($id) { $m = [regex]::Match([string]$id, '\d+'); if ($m.Success) { [int]$m.Value } else { 0 } }
function IdText($id) { [regex]::Replace([string]$id, '\d+', '') }

$Befunde = New-Object System.Collections.Generic.List[object]

# Platzhalterzeilen ("nicht geprüft") erkennt das Skript nur an den vollständigen, festen Texten, die es selbst erzeugt - keine Teilstring-Suche
# in Konto-, Objekt- oder Beschreibungstexten, die ein Angreifer beeinflussen könnte
# Deutsch und Englisch: Skripte erzeugen den Text je nach -Language, erkannt werden beide Fassungen
$PlatzhalterTexte = @('Abfrage fehlgeschlagen - nicht geprüft', 'Berechtigungen nicht lesbar - nicht geprüft', 'SYSVOL nicht lesbar - nicht geprüft', 'WMI-Filter nicht lesbar - nicht geprüft', 'Kein Domänencontroller ermittelbar - SYSVOL nicht geprüft', 'Inhalt des Ordners nicht lesbar - Richtlinie nicht geprüft',
    'Query failed - not checked', 'Permissions not readable - not checked', 'SYSVOL not readable - not checked', 'WMI filter not readable - not checked', 'No domain controller found - SYSVOL not checked', 'Folder content not readable - policy not checked')
function IstPlatzhalter($o) {
    # Ein Skript kann $script:PlatzhalterSpalten setzen: dann zählen nur diese Spalten (Namensspalten sind von Benutzern beeinflussbar)
    foreach ($pr in $o.PSObject.Properties) {
        if ($script:PlatzhalterSpalten -and ($pr.Name -notin $script:PlatzhalterSpalten)) { continue }
        if (($pr.Value -is [string]) -and ($PlatzhalterTexte -ccontains $pr.Value)) { return $true }
    }
    ("$($o.Feststellung)" -clike 'Nicht geprüft - *') -or ("$($o.Feststellung)" -clike 'Not checked - *')
}

# Besteht ein Prüfpunkt nur aus Platzhalterzeilen (Abfrage fehlgeschlagen), ist das kein Mangel dieses Prüfpunkts: als Info führen statt
# mit seiner Stufe, damit es in den Kacheln nicht als hoher Befund zählt. Nur für Prüfpunkte, deren Ergebnis von einer Abfrage abhängt.
function InfoWennNurNichtGeprueft([string]$IdMuster) {
    foreach ($x in ($Befunde | Where-Object { $_.Id -match $IdMuster -and $_.Anzahl -gt 0 -and $_.Stufe -ne 'Info' })) {
        if (-not @($x.Objekte | Where-Object { -not (IstPlatzhalter $_) }).Count) { $x.Stufe = 'Info' }
    }
}

# Prüfpunkte, die für einzelne Server nicht ausgewertet werden konnten (Abfrage fehlgeschlagen), dürfen nicht als "ohne Befund" erscheinen:
# je Server eine Zeile "nicht geprüft" anhängen; hatte der Prüfpunkt sonst keinen Treffer, steht er als Info statt als OK.
function NichtGeprueft([string]$IdMuster, [string[]]$Namen, [string]$Verweis, [string]$Spalte = 'Server', [string]$Grund = $(T 'Abfrage nicht möglich' 'query not possible')) {
    foreach ($x in ($Befunde | Where-Object { $_.Id -match $IdMuster })) {
        $war = $x.Anzahl
        $zeilen = @($Namen | ForEach-Object { [pscustomobject][ordered]@{ $Spalte = $_; Feststellung = (T "Nicht geprüft - $Grund (siehe $Verweis)" "Not checked - $Grund (see $Verweis)"); Details = '' } })
        $x.Objekte = @($x.Objekte) + $zeilen
        $x.Anzahl = $x.Objekte.Count
        if (-not $war) { $x.Stufe = 'Info' }
    }
}
function Befund {
    param([string]$Id, [string]$Bereich, [string]$Titel, [ValidateSet('Hoch', 'Mittel', 'Niedrig', 'Info')][string]$Stufe,
        $Objekte, [string]$Erklaerung, [string]$Empfehlung)
    $liste = @($Objekte | Where-Object { $null -ne $_ })
    $status = $Stufe
    if ($liste.Count -eq 0) { $status = 'OK' }
    $Befunde.Add([pscustomobject]@{
            Id = $Id; Bereich = $Bereich; Titel = $Titel; Stufe = $status; Anzahl = $liste.Count
            Objekte = $liste; Erklaerung = $Erklaerung; Empfehlung = $Empfehlung
        })
}

# Schreibt den HTML-Bericht (und auf Wunsch CSV-Dateien). $Abschnitte: Überschrift -> Objekte oder fertiges HTML,
# erscheinen vor den Befunden. $Anhang: Überschrift -> Text, erscheint am Ende unverändert.
function BerichtSchreiben {
    param([string]$Name, [string]$Datei, [string]$Bezug, [string]$BezugName = $(T 'Domäne' 'Domain'), [System.Collections.IDictionary]$Umgebung,
        [System.Collections.IDictionary]$Abschnitte = @{}, [System.Collections.IDictionary]$Anhang = @{}, [string]$Fuss)
    Write-Host (T '  Bericht schreiben ...' '  Writing report ...')
    $jetzt = Get-Date
    $ziel = $script:Ausgabe
    if (-not $ziel) { $ziel = Join-Path (Get-Location).Path ("{0}_{1}_{2:yyyy-MM-dd_HHmm}.html" -f $Datei, ($Bezug -replace '[^\w.\-]+', '-'), $jetzt) }
    $ziel = [System.IO.Path]::GetFullPath($ziel)
    $ordner = Split-Path $ziel -Parent
    if (-not (Test-Path $ordner)) { New-Item -ItemType Directory -Path $ordner -Force | Out-Null }

    $stufeText = @{ Hoch = (T 'Hoch' 'High'); Mittel = (T 'Mittel' 'Medium'); Niedrig = (T 'Niedrig' 'Low'); Info = 'Info'; OK = 'OK' }
    $rang = @{ Hoch = 0; Mittel = 1; Niedrig = 2; Info = 3; OK = 4 }
    $zahl = @{}
    foreach ($s in 'Hoch', 'Mittel', 'Niedrig', 'Info', 'OK') { $zahl[$s] = @($Befunde | Where-Object Stufe -eq $s).Count }
    $css = @'
body{font-family:Segoe UI,Arial,sans-serif;color:#2b2f36;margin:0;background:#f4f6fa}
.seite{max-width:1100px;margin:0 auto;padding:28px 24px 60px}
h1{color:#1f5fae;margin:0 0 4px;font-size:28px} h2{color:#1f5fae;font-size:19px;margin:34px 0 10px;border-bottom:2px solid #d0d5dd;padding-bottom:6px}
.meta{color:#6b7280;font-size:13px;margin-bottom:22px}
.kacheln{display:flex;gap:14px;flex-wrap:wrap;margin:18px 0}
.kachel{flex:1;min-width:150px;background:#fff;border-radius:10px;padding:14px 18px;border-left:8px solid #999;box-shadow:0 1px 3px rgba(0,0,0,.08)}
.kachel b{display:block;font-size:30px} .kachel span{font-size:13px;color:#6b7280}
table{border-collapse:collapse;width:100%;background:#fff;font-size:13px;margin:8px 0 4px}
th{background:#1f5fae;color:#fff;text-align:left;padding:7px 9px;font-weight:600} td{padding:6px 9px;border-bottom:1px solid #e5e7eb;vertical-align:top;overflow-wrap:break-word}
tr:nth-child(even) td{background:#f9fafb}
.marke{display:inline-block;min-width:58px;text-align:center;padding:2px 9px;border-radius:11px;color:#fff;font-size:12px;font-weight:600}
.m-Hoch{background:#d92d20}.m-Mittel{background:#f79009}.m-Niedrig{background:#ca8a04}.m-OK{background:#12b76a}.m-Info{background:#1f5fae}
.befund{background:#fff;border-radius:10px;padding:16px 20px;margin:14px 0;border-left:8px solid #999;box-shadow:0 1px 3px rgba(0,0,0,.08)}
.befund h3{margin:0 0 6px;font-size:16px} .befund p{margin:5px 0;font-size:14px;line-height:1.45} .befund .emp{color:#14532d}
.Hoch{border-color:#d92d20}.Mittel{border-color:#f79009}.Niedrig{border-color:#eab308}.OK{border-color:#12b76a}.Info{border-color:#1f5fae}
.klein{color:#6b7280;font-size:12px} a{color:#1f5fae;text-decoration:none}
pre{background:#fff;border:1px solid #d0d5dd;border-radius:8px;padding:12px 14px;font-size:12px;white-space:pre-wrap;word-break:break-word}
.fuss{margin-top:40px;color:#6b7280;font-size:12px;border-top:1px solid #d0d5dd;padding-top:12px}
@media print{body{background:#fff}.befund,.kachel{box-shadow:none;border:1px solid #d0d5dd;border-left-width:8px;break-inside:avoid}}
'@
    $h = New-Object System.Text.StringBuilder
    [void]$h.Append("<!DOCTYPE html><html lang='$Language'><head><meta charset='utf-8'><title>$(Html $Name) $(Html $Bezug)</title><style>$css</style></head><body><div class='seite'>")
    [void]$h.Append("<h1>$(Html $Name)</h1><div class='meta'>$(Html $BezugName) <b>$(Html $Bezug)</b> · $(T 'erstellt am' 'created') $($jetzt.ToString((T 'dd.MM.yyyy HH:mm' 'yyyy-MM-dd HH:mm'))) $(T 'von' 'by') $(Html "$env:USERDOMAIN\$env:USERNAME") $(T 'auf' 'on') $(Html $env:COMPUTERNAME)</div>")
    [void]$h.Append("<div class='kacheln'>")
    foreach ($s in 'Hoch', 'Mittel', 'Niedrig', 'Info', 'OK') {
        $text = @{ Hoch = (T 'Befunde mit hoher Priorität' 'findings, high priority'); Mittel = (T 'mit mittlerer Priorität' 'medium priority'); Niedrig = (T 'mit niedriger Priorität' 'low priority'); Info = (T 'Hinweise und nicht geprüft' 'notes and not checked'); OK = (T 'Prüfpunkte ohne Befund' 'checks without findings') }[$s]
        [void]$h.Append("<div class='kachel $s'><b>$($zahl[$s])</b><span>$text</span></div>")
    }
    [void]$h.Append("</div><h2>$(T 'Umgebung' 'Environment')</h2><table><tr><th>$(T 'Eigenschaft' 'Property')</th><th>$(T 'Wert' 'Value')</th></tr>")
    foreach ($k in $Umgebung.Keys) { [void]$h.Append("<tr><td>$(Html (WertAnzeige $k))</td><td>$(Html (WertAnzeige $Umgebung[$k]))</td></tr>") }
    [void]$h.Append("</table>")

    [void]$h.Append("<h2>$(T 'Übersicht der Prüfpunkte' 'Overview of checks')</h2><table><tr><th>$(T 'Nr.' 'No.')</th><th>$(T 'Bereich' 'Area')</th><th>$(T 'Prüfpunkt' 'Check')</th><th>$(T 'Treffer' 'Hits')</th><th>$(T 'Bewertung' 'Rating')</th></tr>")
    foreach ($x in $Befunde) {
        [void]$h.Append("<tr><td>$($x.Id)</td><td>$(Html $x.Bereich)</td><td><a href='#$($x.Id)'>$(Html $x.Titel)</a></td><td>$($x.Anzahl)</td><td><span class='marke m-$($x.Stufe)'>$($stufeText[$x.Stufe])</span></td></tr>")
    }
    [void]$h.Append("</table>")

    foreach ($k in $Abschnitte.Keys) {
        [void]$h.Append("<h2>$(Html (WertAnzeige $k))</h2>")
        $inhalt = $Abschnitte[$k]
        if ($inhalt -is [string]) { [void]$h.Append($inhalt) }
        elseif (@($inhalt).Count) { [void]$h.Append(((Einheitlich $inhalt | ConvertTo-Html -Fragment) -join "`n")) }
        else { [void]$h.Append("<p class='klein'>$(T 'Keine Einträge.' 'No entries.')</p>") }
    }

    [void]$h.Append("<h2>$(T 'Befunde' 'Findings')</h2>")
    $offen = @($Befunde | Where-Object { $_.Stufe -ne 'OK' } | Sort-Object { $rang[$_.Stufe] }, { IdText $_.Id }, { IdZahl $_.Id })
    foreach ($x in $offen) {
        [void]$h.Append("<div class='befund $($x.Stufe)' id='$($x.Id)'><h3><span class='marke m-$($x.Stufe)'>$($stufeText[$x.Stufe])</span> $($x.Id) · $(Html $x.Titel) <span class='klein'>($($x.Anzahl) $(T 'Treffer' 'hits'))</span></h3>")
        [void]$h.Append("<p>$(Html $x.Erklaerung)</p><p class='emp'><b>$(T 'Empfehlung' 'Recommendation'):</b> $(Html $x.Empfehlung)</p>")
        [void]$h.Append(((Einheitlich $x.Objekte | ConvertTo-Html -Fragment) -join "`n"))
        [void]$h.Append("</div>")
    }
    if (-not $offen.Count) { [void]$h.Append("<p>$(T 'Keine Auffälligkeiten gefunden.' 'No anomalies found.')</p>") }
    $ok = @($Befunde | Where-Object Stufe -eq 'OK')
    if ($ok.Count) {
        [void]$h.Append("<h2>$(T 'Ohne Befund' 'No findings')</h2><table><tr><th>$(T 'Nr.' 'No.')</th><th>$(T 'Prüfpunkt' 'Check')</th></tr>")
        foreach ($x in $ok) { [void]$h.Append("<tr id='$($x.Id)'><td>$($x.Id)</td><td>$(Html $x.Titel)</td></tr>") }
        [void]$h.Append("</table>")
    }
    foreach ($k in $Anhang.Keys) { [void]$h.Append("<h2>$(Html $k)</h2><pre>$(Html $Anhang[$k])</pre>") }
    [void]$h.Append("<div class='fuss'>$(Html $Name) Version $script:Version · IT Admin Tools by MM · $(T 'Das Skript hat ausschließlich gelesen und nichts verändert.' 'The script only read and changed nothing.') $(Html $Fuss)</div>")
    [void]$h.Append("</div></body></html>")
    [System.IO.File]::WriteAllText($ziel, $h.ToString(), (New-Object System.Text.UTF8Encoding($true)))

    $basis = [System.IO.Path]::ChangeExtension($ziel, $null).TrimEnd('.')
    if ($script:Csv) {
        foreach ($x in ($Befunde | Where-Object { $_.Anzahl -gt 0 })) {
            Einheitlich $x.Objekte | Export-Csv -Path "${basis}_$($x.Id).csv" -NoTypeInformation -Delimiter ';' -Encoding UTF8
        }
    }
    Write-Host ''
    Write-Host ((T "Fertig: {0} hoch, {1} mittel, {2} niedrig, {3} ohne Befund." "Done: {0} high, {1} medium, {2} low, {3} without findings.") -f $zahl.Hoch, $zahl.Mittel, $zahl.Niedrig, $zahl.OK) -ForegroundColor Green
    Write-Host ((T 'Bericht' 'Report') + ": $ziel")
    if (-not $script:NichtOeffnen -and [Environment]::UserInteractive) { try { Start-Process $ziel } catch { } }
    $basis
}

function Zeile($server, $was, $details = '') { [pscustomobject]@{ Server = $server; Feststellung = $was; Details = $details } }
# Eine fehlgeschlagene Abfrage ist selbst eine Feststellung - sonst sähe der Prüfpunkt fälschlich sauber aus
function Fehlzeile($server, $fehler, $was = '') { Zeile $server ((T "Abfrage fehlgeschlagen - nicht geprüft" "Query failed - not checked") + $(if ($was) { " ($was)" })) (Kurz $fehler.Exception.Message) }
function Kurzname($n) { ("$n" -split '\.')[0].ToUpper() }

Write-Host (T 'DNS- und DHCP-Bericht - es wird nur gelesen, nichts verändert.' 'DNS and DHCP report - read-only, nothing is changed.') -ForegroundColor Cyan
$dom = Get-ADDomain
$jetzt = Get-Date
$dcs = @(Get-ADDomainController -Filter *)
$dcNamen = @($dcs | ForEach-Object { Kurzname $_.Name })
$dnsUebersicht = @(); $zonenUebersicht = @(); $dhcpUebersicht = @(); $bereichUebersicht = @()
$dnsAdressen = @()

# ================================================================== DNS
if (-not $OhneDns) {
    $n1 = @(); $n2 = @(); $n3 = @(); $n4 = @(); $n5 = @(); $n6 = @(); $n7 = @(); $n8 = @(); $n9 = @(); $n10 = @(); $n11 = @()
    $modul = [bool](Get-Module -ListAvailable -Name DnsServer)
    if (-not $modul) { $n1 += Zeile $env:COMPUTERNAME (T 'Modul "DnsServer" fehlt - DNS nicht geprüft' 'Module "DnsServer" is missing - DNS not checked') (T 'Auf einem DNS-Server starten oder RSAT-DNS-Server installieren' 'Start on a DNS server or install RSAT-DNS-Server') }
    else {
        Import-Module DnsServer
        if (-not $DnsServer) {
            try { $DnsServer = @(Resolve-DnsName -Name $dom.DNSRoot -Type NS -ErrorAction Stop | Where-Object { $_.Type -eq 'NS' } | ForEach-Object { $_.NameHost.TrimEnd('.') } | Sort-Object -Unique) }
            catch { $n1 += Fehlzeile $dom.DNSRoot $_ (T 'Namenserver der Domäne ermitteln' 'Identify the domain''s name servers') }
        }
        $zonenGesehen = @{}
        foreach ($srv in $DnsServer) {
            $name = Kurzname $srv
            Write-Host (T "  DNS-Server $name ..." "DNS server $name ...")
            try { $einst = Get-DnsServerScavenging -ComputerName $srv -ErrorAction Stop }
            catch { $n1 += Fehlzeile $name $_; continue }
            try { $dnsAdressen += @(Resolve-DnsName -Name $srv -Type A -ErrorAction Stop | Where-Object { $_.Type -eq 'A' } | ForEach-Object { $_.IPAddress }) } catch { }

            # --- Alterung auf dem Server
            if (-not $einst.ScavengingState) { $n2 += Zeile $name (T 'Automatisches Aufräumen veralteter Einträge ist ausgeschaltet' 'Automatic scavenging of stale entries is disabled') }
            elseif ($einst.LastScavengeTime -and $einst.LastScavengeTime -lt $jetzt.AddDays(-30)) { $n2 += Zeile $name (T 'Aufräumen eingeschaltet, aber seit über 30 Tagen nicht gelaufen' 'Scavenging is enabled but has not run for over 30 days') (T "Letzter Lauf: $(Datum $einst.LastScavengeTime)" "Last run: $(Datum $einst.LastScavengeTime)") }

            # --- Weiterleitungen
            $weiter = @()
            try {
                $fw = Get-DnsServerForwarder -ComputerName $srv -ErrorAction Stop
                $weiter = @($fw.IPAddress | ForEach-Object { "$_" } | Where-Object { $_ })
                foreach ($ip in $weiter) {
                    try { Resolve-DnsName -Name '.' -Type NS -Server $ip -DnsOnly -QuickTimeout -ErrorAction Stop | Out-Null }
                    catch {
                        # Antworten wie "Name nicht gefunden" oder "Serverfehler" zeigen, dass der Server erreichbar ist
                        if ($_.Exception.NativeErrorCode -notin 9002, 9003, 9501) { $n8 += Zeile $name (T "Weiterleitung $ip antwortet nicht" "Forwarding $ip does not respond") (Kurz $_.Exception.Message) }
                    }
                }
                if ($weiter.Count -eq 1) { $n8 += Zeile $name (T 'Nur eine Weiterleitung eingetragen' 'Only one forwarding entry configured') (T "Fällt $($weiter[0]) aus, verzögert sich die Namensauflösung nach außen" "If $($weiter[0]) fails, name resolution to the outside is delayed") }
            } catch { $n8 += Fehlzeile $name $_ 'Weiterleitungen' }

            # --- Zonen
            try { $zonen = @(Get-DnsServerZone -ComputerName $srv -ErrorAction Stop | Where-Object { -not $_.IsAutoCreated -and $_.ZoneName -ne 'TrustAnchors' }) }
            catch { $n1 += Fehlzeile $name $_ 'Zonen'; continue }
            $dnsUebersicht += [pscustomobject][ordered]@{
                Server = $name; Zonen = $zonen.Count; 'Aufräumen' = JaNein $einst.ScavengingState
                'Letzter Aufräumlauf' = Datum $einst.LastScavengeTime; Weiterleitungen = $(if ($weiter.Count) { $weiter -join ', ' } else { (T 'keine (Stammhinweise)' 'none (root hints)') })
            }
            if (@($zonen | Where-Object { $_.ZoneName -eq '.' }).Count) { $n11 += Zeile $name (T 'Der Server führt eine Stammzone "."' 'The server hosts a root zone "."') (T 'Er hält sich damit für die Wurzel des DNS und löst keine Namen im Internet auf' 'It thereby considers itself the DNS root and does not resolve names on the Internet.') }
            if (-not @($zonen | Where-Object { $_.IsReverseLookupZone -and $_.ZoneType -eq 'Primary' }).Count) { $n10 += Zeile $name (T 'Keine Reverse-Lookupzone vorhanden' 'No reverse lookup zone exists') }

            foreach ($z in $zonen) {
                $erst = -not $zonenGesehen.ContainsKey($z.ZoneName)
                if ($erst) {
                    $zonenGesehen[$z.ZoneName] = $true
                    $zonenUebersicht += [pscustomobject][ordered]@{
                        Zone = $z.ZoneName; Typ = "$($z.ZoneType)"; 'Im AD gespeichert' = JaNein $z.IsDsIntegrated
                        'Dynamische Updates' = "$($z.DynamicUpdate)"; 'Zonenübertragung' = "$($z.SecureSecondaries)"; 'Gelesen von' = $name
                    }
                }
                if ($z.ZoneType -ne 'Primary') { continue }
                # Im AD gespeicherte Zonen sind auf allen Servern gleich - einmal melden genügt
                if ($z.IsDsIntegrated -and -not $erst) { continue }
                if ("$($z.DynamicUpdate)" -eq 'NonsecureAndSecure') { $n5 += Zeile $name (T "Zone $($z.ZoneName) nimmt unsichere dynamische Updates an" "Zone $($z.ZoneName) accepts insecure dynamic updates") }
                if ("$($z.SecureSecondaries)" -eq 'TransferAnyServer') { $n7 += Zeile $name (T "Zone $($z.ZoneName) darf an jeden Server übertragen werden" "Zone $($z.ZoneName) may be transferred to any server") }
                if (-not $z.IsDsIntegrated) { $n6 += Zeile $name (T "Zone $($z.ZoneName) liegt nur als Datei auf diesem Server" "Zone $($z.ZoneName) is stored only as a file on this server") 'Nicht im Active Directory gespeichert' }
                if ("$($z.DynamicUpdate)" -eq 'None') { continue }
                try {
                    $alter = Get-DnsServerZoneAging -Name $z.ZoneName -ComputerName $srv -ErrorAction Stop
                    if (-not $alter.AgingEnabled) { $n3 += Zeile $name (T "Zone $($z.ZoneName): Alterung ausgeschaltet" "Zone $($z.ZoneName): Aging disabled") (T 'Veraltete dynamische Einträge werden nie entfernt' 'Outdated dynamic entries are never removed') }
                } catch { $n3 += Fehlzeile $name $_ (T "Alterung der Zone $($z.ZoneName)" "Zone aging for zone $($z.ZoneName)") }
                if ($z.IsReverseLookupZone -or $z.ZoneName -like '_msdcs.*') { continue }
                try {
                    $eintraege = @(Get-DnsServerResourceRecord -ZoneName $z.ZoneName -ComputerName $srv -RRType A -ErrorAction Stop | Where-Object { $_.HostName -notin '@', 'DomainDnsZones', 'ForestDnsZones' })
                    $grenze = $jetzt.AddDays(-$VeraltetTage)
                    foreach ($e in ($eintraege | Where-Object { $_.Timestamp -and $_.Timestamp -lt $grenze } | Sort-Object Timestamp)) {
                        $n4 += Zeile $name (T "$($e.HostName).$($z.ZoneName) zuletzt aktualisiert am $(Datum $e.Timestamp)" "$($e.HostName).$($z.ZoneName) last updated on $(Datum $e.Timestamp)") (T "Adresse $($e.RecordData.IPv4Address)" "Address $($e.RecordData.IPv4Address)")
                    }
                    # Mehrere dynamisch eingetragene Namen auf derselben Adresse: fast immer ein Überbleibsel
                    foreach ($gr in ($eintraege | Where-Object Timestamp | Group-Object { "$($_.RecordData.IPv4Address)" } | Where-Object Count -gt 1)) {
                        $n9 += Zeile $name (T "Adresse $($gr.Name) ist für $($gr.Count) Namen eingetragen" "Address $($gr.Name) is registered for $($gr.Count) names") (($gr.Group | ForEach-Object { $_.HostName }) -join ', ')
                    }
                } catch { $n4 += Fehlzeile $name $_ (T "Einträge der Zone $($z.ZoneName)" "Entries for zone $($z.ZoneName)") }
            }
        }
    }
    Befund 'N1' 'DNS' (T 'DNS-Server nicht abfragbar' 'DNS server not queryable') 'Hoch' $n1 `
        (T 'Der Server ist als Namenserver der Domäne eingetragen, lässt sich aber nicht abfragen. Für ihn wurde nichts geprüft.' 'The server is registered as a name server for the domain, but cannot be queried. Nothing was checked for it.') `
        (T 'Prüfen, ob der Server läuft, ob das Konto DNS verwalten darf und ob die Firewall die Fernverwaltung zulässt. Existiert der Server nicht mehr, seinen NS-Eintrag aus den Zonen entfernen.' 'Check whether the server is running, whether the account is permitted to manage DNS, and whether the firewall allows remote administration. If the server no longer exists, remove its NS entry from the zones.')
    Befund 'N3' 'DNS' (T 'Zonen ohne Alterung' 'Zones without aging') 'Mittel' $n3 `
        (T 'Das Aufräumen wirkt nur in Zonen, in denen die Alterung eingeschaltet ist. Geprüft werden Zonen mit dynamischen Updates.' 'Cleanup only takes effect in zones where aging is enabled. Zones with dynamic updates are checked.') `
        (T 'In den Eigenschaften der Zone unter "Alterung" das Aufräumen veralteter Einträge aktivieren (Standardwerte: 7 Tage + 7 Tage).' 'In the zone properties under Aging, enable scavenging of stale entries (default values: 7 days + 7 days).')
    Befund 'N5' 'DNS' (T 'Zonen mit unsicheren dynamischen Updates' 'Zones with insecure dynamic updates') 'Hoch' $n5 `
        (T 'Jedes Gerät im Netz kann ohne Anmeldung Einträge anlegen oder überschreiben - auch den Namen eines Servers.' 'Any device on the network can create or overwrite entries without logon - including a server name.') `
        (T 'Zone im Active Directory speichern und dynamische Updates auf "Nur sichere" stellen.' 'Store the zone in Active Directory and set dynamic updates to "Secure only".')
}

# ================================================================== DHCP
if (-not $OhneDhcp) {
    $h1 = @(); $h2 = @(); $h3 = @(); $h4 = @(); $h5 = @(); $h6 = @(); $h7 = @(); $h8 = @(); $h9 = @(); $h10 = @()
    $modul = [bool](Get-Module -ListAvailable -Name DhcpServer)
    if (-not $modul) { $h1 += Zeile $env:COMPUTERNAME (T 'Modul "DhcpServer" fehlt - DHCP nicht geprüft' 'Module "DhcpServer" is missing - DHCP not checked') (T 'Auf einem DHCP-Server starten oder RSAT-DHCP installieren (oder -OhneDhcp angeben)' 'Start on a DHCP server or install RSAT-DHCP (or specify -OhneDhcp)') }
    else {
        Import-Module DhcpServer
        if (-not $DhcpServer) {
            try { $DhcpServer = @(Get-DhcpServerInDC -ErrorAction Stop | ForEach-Object { $_.DnsName } | Sort-Object -Unique) }
            catch { $h1 += Fehlzeile $dom.DNSRoot $_ 'autorisierte DHCP-Server ermitteln' }
        }
        if (-not $dnsAdressen.Count) { $dnsAdressen = @($dcs | ForEach-Object { $_.IPv4Address }) }
        foreach ($srv in $DhcpServer) {
            $name = Kurzname $srv
            Write-Host (T "  DHCP-Server $name ..." "DHCP server $name ...")
            try { $bereiche = @(Get-DhcpServerv4Scope -ComputerName $srv -ErrorAction Stop) }
            catch { $h1 += Fehlzeile $name $_; continue }
            $statistik = @{}
            try { Get-DhcpServerv4ScopeStatistics -ComputerName $srv -ErrorAction Stop | ForEach-Object { $statistik["$($_.ScopeId)"] = $_ } } catch { $h2 += Fehlzeile $name $_ 'Auslastung' }
            $schutz = @{}
            $failoverGelesen = $false
            try {
                foreach ($f in @(Get-DhcpServerv4Failover -ComputerName $srv -ErrorAction Stop)) {
                    foreach ($id in $f.ScopeId) { $schutz["$id"] = $f }
                    if ("$($f.State)" -ne 'Normal') { $h5 += Zeile $name (T "Failover-Beziehung '$($f.Name)' im Zustand $($f.State)" "Failover relationship '$($f.Name)' in state $($f.State)") (T "Partner: $($f.PartnerServer), Modus: $($f.Mode)" "Partner: $($f.PartnerServer), Mode: $($f.Mode)") }
                }
                $failoverGelesen = $true
            } catch { $h4 += Fehlzeile $name $_ 'Failover' }
            $serverOpt = @{}
            $serverOptOk = $true
            try { Get-DhcpServerv4OptionValue -ComputerName $srv -All -ErrorAction Stop | ForEach-Object { $serverOpt[[int]$_.OptionId] = $_.Value } }
            catch { $serverOptOk = $false; $h6 += Fehlzeile $name $_ 'Serveroptionen' }

            foreach ($b in $bereiche) {
                $id = "$($b.ScopeId)"
                $st = $statistik[$id]
                $bereichUebersicht += [pscustomobject][ordered]@{
                    Server = $name; Bereich = $id; Name = $b.Name; Von = "$($b.StartRange)"; Bis = "$($b.EndRange)"; Zustand = "$($b.State)"
                    'Lease-Dauer' = $(if ($b.LeaseDuration -eq [timespan]::MaxValue) { 'unbegrenzt' } else { (T "{0:N1} Tage" "{0:N1} days") -f $b.LeaseDuration.TotalDays })
                    Belegt = $(if ($st) { $st.InUse } else { '?' }); Frei = $(if ($st) { $st.Free } else { '?' })
                    'Auslastung' = $(if ($st) { "{0:N0} %" -f $st.PercentageInUse } else { '?' }); Failover = $(if ($schutz[$id]) { $schutz[$id].Name } else { 'nein' })
                }
                if ("$($b.State)" -ne 'Active') { $h3 += Zeile $name (T "Bereich $id ($($b.Name)) ist deaktiviert" "Scope $id ($($b.Name)) is disabled"); continue }
                if ($st -and $st.PercentageInUse -ge $AuslastungProzent) { $h2 += Zeile $name ((T "Bereich $id ($($b.Name)) zu {0:N0} % belegt" "Scope $id ($($b.Name)) is {0:N0} % in use") -f $st.PercentageInUse) (T "$($st.InUse) belegt, $($st.Free) frei, $($st.Reserved) reserviert" "$($st.InUse) in use, $($st.Free) free, $($st.Reserved) reserved") }
                # Ließ sich Failover nicht lesen, steht das schon als Fehlzeile da - nicht zusätzlich jeden Bereich als ungeschützt melden
                if (-not $schutz[$id] -and $failoverGelesen) { $h4 += Zeile $name (T "Bereich $id ($($b.Name)) hat keinen Ausfallschutz (Failover)" "Scope $id ($($b.Name)) has no failover protection (Failover)") }
                if ($b.LeaseDuration -eq [timespan]::MaxValue) { $h7 += Zeile $name (T "Bereich $id ($($b.Name)): Lease-Dauer unbegrenzt" "Scope $id ($($b.Name)): lease duration unlimited") }
                elseif ($b.LeaseDuration.TotalDays -gt 30) { $h7 += Zeile $name ((T "Bereich $id ($($b.Name)): Lease-Dauer {0:N0} Tage" "Scope $id ($($b.Name)): lease duration {0:N0} days") -f $b.LeaseDuration.TotalDays) }

                # --- Optionen: Bereich hat Vorrang vor Server
                $opt = @{}
                foreach ($k in $serverOpt.Keys) { $opt[$k] = $serverOpt[$k] }
                try { Get-DhcpServerv4OptionValue -ComputerName $srv -ScopeId $b.ScopeId -All -ErrorAction Stop | ForEach-Object { $opt[[int]$_.OptionId] = $_.Value } }
                catch { $h6 += Fehlzeile $name $_ (T "Optionen des Bereichs $id" "Options for scope $id"); continue }
                # Sind die Serveroptionen nicht lesbar, sagt ein fehlender Wert nichts aus
                if (-not $opt[3]) { if ($serverOptOk) { $h6 += Zeile $name (T "Bereich $id ($($b.Name)): Option 003 Router fehlt" "Scope $id ($($b.Name)): Option 003 Router missing") (T 'Geräte erhalten kein Standardgateway' 'Devices do not receive a default gateway') } }
                if (-not $opt[6]) { if ($serverOptOk) { $h6 += Zeile $name (T "Bereich $id ($($b.Name)): Option 006 DNS-Server fehlt" "Scope $id ($($b.Name)): Option 006 DNS Server missing") } }
                else {
                    $fremd = @($opt[6] | Where-Object { $_ -notin $dnsAdressen })
                    if ($fremd.Count) { $h6 += Zeile $name (T "Bereich $id ($($b.Name)): DNS-Server, der kein DNS-Server der Domäne ist" "Scope $id ($($b.Name)): DNS server that is not a DNS server for the domain") "Verteilt: $($opt[6] -join ', ') - fremd: $($fremd -join ', ')" }
                    if (@($opt[6]).Count -eq 1 -and $dnsAdressen.Count -gt 1) { $h6 += Zeile $name (T "Bereich $id ($($b.Name)): nur ein DNS-Server verteilt" "Scope $id ($($b.Name)): only one DNS server provided") "Verteilt: $($opt[6] -join ', ')" }
                }
                if ($opt[15] -and "$($opt[15])" -ne $dom.DNSRoot) { $h6 += Zeile $name (T "Bereich $id ($($b.Name)): Option 015 DNS-Domänenname weicht ab" "Scope $id ($($b.Name)): Option 015 DNS domain name differs") "Verteilt: $($opt[15]), Domäne: $($dom.DNSRoot)" }

                try {
                    $schlecht = @(Get-DhcpServerv4Lease -ComputerName $srv -ScopeId $b.ScopeId -ErrorAction Stop | Where-Object { "$($_.AddressState)" -eq 'Declined' -or $_.HostName -eq 'BAD_ADDRESS' })
                    if ($schlecht.Count) { $h8 += Zeile $name (T "Bereich $id ($($b.Name)): $($schlecht.Count) Adressen als Konflikt markiert (BAD_ADDRESS)" "Scope $id ($($b.Name)): $($schlecht.Count) addresses marked as conflicts (BAD_ADDRESS)") (($schlecht | Select-Object -First 15 | ForEach-Object { "$($_.IPAddress)" }) -join ', ') }
                } catch { $h8 += Fehlzeile $name $_ (T "Leases des Bereichs $id" "Leases for scope $id") }
            }

            $zugang = ''
            try {
                $zug = Get-DhcpServerDnsCredential -ComputerName $srv -ErrorAction Stop
                $zugang = $zug.UserName
                if (-not $zugang -and $name -in $dcNamen) { $h9 += Zeile $name (T 'DHCP läuft auf einem Domänencontroller ohne eigenes Konto für DNS-Einträge' 'DHCP runs on a domain controller without a dedicated account for DNS entries') }
            } catch { $h9 += Fehlzeile $name $_ 'Konto für DNS-Einträge' }
            $protokoll = '?'
            try { $log = Get-DhcpServerAuditLog -ComputerName $srv -ErrorAction Stop; $protokoll = JaNein $log.Enable; if (-not $log.Enable) { $h10 += Zeile $name 'DHCP-Überwachungsprotokoll ist ausgeschaltet' } }
            catch { $h10 += Fehlzeile $name $_ 'Überwachungsprotokoll' }
            $dhcpUebersicht += [pscustomobject][ordered]@{
                Server = $name; Bereiche = $bereiche.Count; 'Auf Domänencontroller' = JaNein ($name -in $dcNamen)
                'Konto für DNS-Einträge' = $(if ($zugang) { $zugang } else { 'keines' }); 'Überwachungsprotokoll' = $protokoll
            }
        }
    }
    Befund 'H1' 'DHCP' (T 'DHCP-Server nicht abfragbar' 'DHCP server not queryable') 'Hoch' $h1 `
        (T 'Der Server ist im Active Directory als DHCP-Server autorisiert, lässt sich aber nicht abfragen. Für ihn wurde nichts geprüft. Ist kein Windows-DHCP-Server autorisiert (DHCP läuft z. B. auf Router oder Firewall), bleibt der DHCP-Teil leer.' 'The server is authorized as a DHCP server in Active Directory, but cannot be queried. Nothing was checked for it. If no Windows DHCP server is authorized (DHCP is running, for example, on a router or firewall), the DHCP section remains empty.') `
        (T 'Prüfen, ob der Server läuft und das Konto DHCP verwalten darf. Existiert der Server nicht mehr, die Autorisierung im Active Directory entfernen.' 'Check whether the server is running and whether the account is permitted to manage DHCP. If the server no longer exists, remove the authorization from Active Directory.')
    Befund 'H2' 'DHCP' (T "Bereiche mit mindestens $AuslastungProzent % Auslastung" "Scopes with at least $AuslastungProzent % utilization") 'Hoch' $h2 `
        (T 'Ist ein Bereich voll, erhalten neue Geräte keine Adresse mehr - meist fällt das zuerst bei Besuchern und im WLAN auf.' 'If a scope is full, new devices no longer receive an address - usually this is first noticed for guests and in the Wi-Fi.') `
        (T 'Bereich vergrößern, Lease-Dauer verkürzen (z. B. 8 Stunden im Gäste-WLAN) oder ungenutzte Reservierungen entfernen.' 'Increase scope, shorten lease duration (e.g., 8 hours in guest Wi-Fi) or remove unused reservations.')
}

$umgebung = [ordered]@{
    (T 'Domäne (NetBIOS)' 'Domain (NetBIOS)') = "$($dom.DNSRoot) ($($dom.NetBIOSName))"
    (T 'Geprüfte DNS-Server' 'Checked DNS servers') = $(if ($OhneDns) { (T 'übersprungen' 'skipped') } elseif ($DnsServer) { ($DnsServer | ForEach-Object { Kurzname $_ }) -join ', ' } else { (T 'keine' 'none') })
    (T 'Geprüfte DHCP-Server' 'Checked DHCP servers') = $(if ($OhneDhcp) { (T 'übersprungen' 'skipped') } elseif ($DhcpServer) { ($DhcpServer | ForEach-Object { Kurzname $_ }) -join ', ' } else { (T 'keine im Active Directory autorisiert' 'none authorized in Active Directory') })
    (T 'Schwellen dieses Berichts' 'Thresholds for this report') = (T "DNS-Einträge veraltet ab $VeraltetTage Tagen, DHCP-Auslastung ab $AuslastungProzent %" "DNS entries stale starting at $VeraltetTage days, DHCP utilization starting at $AuslastungProzent %")
}
$abschnitte = [ordered]@{}
if (-not $OhneDns) { $abschnitte[(T 'DNS-Server' 'DNS servers')] = $dnsUebersicht; $abschnitte[(T 'DNS-Zonen' 'DNS zones')] = $zonenUebersicht }
if (-not $OhneDhcp) { $abschnitte[(T 'DHCP-Server' 'DHCP servers')] = $dhcpUebersicht; $abschnitte[(T 'DHCP-Bereiche' 'DHCP scopes')] = $bereichUebersicht }
BerichtSchreiben -Name (T 'DNS- und DHCP-Bericht Light' 'DNS and DHCP report Light') -Datei 'DNS-DHCP-Bericht' -Bezug $dom.DNSRoot -Umgebung $umgebung -Abschnitte $abschnitte `
    -Fuss (T 'Light-Version mit 5 von 21 Prüfpunkten der Vollversion (https://mueller86.gumroad.com/l/sthgh). Der Bericht zeigt Auffälligkeiten anhand fester Regeln zum Zeitpunkt des Laufs; er ersetzt keine laufende Überwachung und erhebt keinen Anspruch auf Vollständigkeit. Dieser Bericht enthält Servernamen und Adressen - bitte vertraulich behandeln.' 'Light version with 5 of 21 checks of the full version (https://mueller86.gumroad.com/l/sthgh). The report shows anomalies based on fixed rules at the time of the run; it does not replace ongoing monitoring and makes no claim to completeness. This report contains server names and addresses - please treat as confidential.') | Out-Null
if ($PassThru) { $Befunde }
