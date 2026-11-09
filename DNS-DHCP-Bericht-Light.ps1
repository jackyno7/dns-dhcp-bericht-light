#Requires -Version 5.1
<#
.SYNOPSIS
    LIGHT-VERSION (5 von 21 Prüfpunkten, kostenlos). DNS- und DHCP-Bericht: prüft die Windows-DNS-Server und DHCP-Server einer Domäne und erzeugt einen
    HTML-Bericht zu Alterung, veralteten Einträgen, unsicheren Zonen, Weiterleitungen, Auslastung der
    DHCP-Bereiche, Ausfallschutz und Optionen.

.DESCRIPTION
    Das Skript arbeitet ausschließlich LESEND. Es ändert keine Zonen, Einträge, Bereiche oder Einstellungen,
    löscht nichts und überträgt keine Daten. Es schreibt genau eine HTML-Datei (und auf Wunsch CSV-Dateien)
    in den angegebenen Ausgabeordner.

    Voraussetzungen: Windows PowerShell 5.1, die Module "ActiveDirectory", "DnsServer" und "DhcpServer"
    (auf Servern mit der jeweiligen Rolle vorhanden, sonst RSAT) und ein Konto, das die DNS- und DHCP-Server
    verwalten darf (z. B. Domänen-Admin). Was sich nicht abfragen lässt, erscheint im Bericht als Befund -
    es wird nie stillschweigend als "in Ordnung" gewertet.

.PARAMETER Ausgabe
    Pfad der HTML-Datei. Standard: DNS-DHCP-Bericht_<Domäne>_<Datum>.html im aktuellen Ordner.

.PARAMETER DnsServer
    DNS-Server, die geprüft werden. Standard: alle Namenserver der Domänenzone.

.PARAMETER DhcpServer
    DHCP-Server, die geprüft werden. Standard: alle im Active Directory autorisierten DHCP-Server.

.PARAMETER VeraltetTage
    Dynamische DNS-Einträge, die länger nicht aktualisiert wurden, gelten als veraltet (Standard 60).

.PARAMETER AuslastungProzent
    DHCP-Bereiche ab dieser Auslastung werden gemeldet (Standard 80).

.PARAMETER OhneDns
    Überspringt den DNS-Teil.

.PARAMETER OhneDhcp
    Überspringt den DHCP-Teil.

.PARAMETER Csv
    Schreibt zusätzlich je Prüfpunkt mit Treffern eine CSV-Datei neben den Bericht.

.PARAMETER NichtOeffnen
    Öffnet den fertigen Bericht nicht automatisch im Browser.

.PARAMETER PassThru
    Gibt die Befunde zusätzlich als Objekte zurück (für eigene Auswertungen oder geplante Aufgaben).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\DNS-DHCP-Bericht.ps1

.EXAMPLE
    .\DNS-DHCP-Bericht.ps1 -DhcpServer dhcp01 -AuslastungProzent 70 -Csv

.NOTES
    IT Admin Tools by MM - Version 1.0 (10.2026)
    Kein Ersatz für eine Überwachung oder Sicherheitsprüfung. Nutzung auf eigene Verantwortung.
#>
[CmdletBinding()]
param(
    [string]$Ausgabe,
    [string[]]$DnsServer,
    [string[]]$DhcpServer,
    [ValidateRange(1, 3650)][int]$VeraltetTage = 60,
    [ValidateRange(1, 100)][int]$AuslastungProzent = 80,
    [switch]$OhneDns,
    [switch]$OhneDhcp,
    [switch]$Csv,
    [switch]$NichtOeffnen,
    [switch]$PassThru
)

$ErrorActionPreference = 'Stop'
$Version = '1.0'

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Host 'Das PowerShell-Modul "ActiveDirectory" fehlt.' -ForegroundColor Red
    Write-Host 'Windows Server:  Install-WindowsFeature RSAT-AD-PowerShell, RSAT-DNS-Server, RSAT-DHCP'
    exit 2
}
Import-Module ActiveDirectory

# ------------------------------------------------------------------ Hilfsfunktionen
function Datum($d, $leer = 'nie') { if ($d) { ([datetime]$d).ToString('dd.MM.yyyy') } else { $leer } }
function JaNein($b) { if ($b) { 'Ja' } else { 'Nein' } }
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
        $sicher | Microsoft.PowerShell.Utility\Export-Csv -Path $Path -NoTypeInformation:$NoTypeInformation -Delimiter $Delimiter -Encoding $Encoding
    }
}

# Tabellen: ConvertTo-Html und Export-Csv nehmen die Spalten des ersten Objekts. Haben die Zeilen einer Liste verschiedene
# Eigenschaften (z. B. Fehlzeile neben normalen Treffern), gingen Spalten verloren: alle Namen der Reihe nach vereinigen.
function Einheitlich($liste) {
    $liste = @($liste | Where-Object { $null -ne $_ })
    if ($liste.Count -lt 2) { return $liste }
    $namen = New-Object System.Collections.Generic.List[string]
    foreach ($o in $liste) { foreach ($p in $o.PSObject.Properties.Name) { if (-not $namen.Contains($p)) { $namen.Add($p) } } }
    if ($namen.Count -eq @($liste[0].PSObject.Properties.Name).Count) { return $liste }
    @($liste | Select-Object -Property $namen)
}
# Sortierschluessel fuer Nummern wie K2, K10: erst Buchstaben, dann die Zahl als Zahl
function IdZahl($id) { $m = [regex]::Match([string]$id, '\d+'); if ($m.Success) { [int]$m.Value } else { 0 } }
function IdText($id) { [regex]::Replace([string]$id, '\d+', '') }

$Befunde = New-Object System.Collections.Generic.List[object]

# Platzhalterzeilen ("nicht geprüft") erkennt das Skript nur an den vollständigen, festen Texten, die es selbst erzeugt - keine Teilstring-Suche
# in Konto-, Objekt- oder Beschreibungstexten, die ein Angreifer beeinflussen könnte
$PlatzhalterTexte = @('Abfrage fehlgeschlagen - nicht geprüft', 'Berechtigungen nicht lesbar - nicht geprüft', 'SYSVOL nicht lesbar - nicht geprüft', 'WMI-Filter nicht lesbar - nicht geprüft', 'Kein Domänencontroller ermittelbar - SYSVOL nicht geprüft', 'Inhalt des Ordners nicht lesbar - Richtlinie nicht geprüft')
function IstPlatzhalter($o) {
    # Ein Skript kann $script:PlatzhalterSpalten setzen: dann zählen nur diese Spalten (Namensspalten sind von Benutzern beeinflussbar)
    foreach ($pr in $o.PSObject.Properties) {
        if ($script:PlatzhalterSpalten -and ($pr.Name -notin $script:PlatzhalterSpalten)) { continue }
        if (($pr.Value -is [string]) -and ($PlatzhalterTexte -ccontains $pr.Value)) { return $true }
    }
    ("$($o.Feststellung)" -clike 'Nicht geprüft - *')
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
function NichtGeprueft([string]$IdMuster, [string[]]$Namen, [string]$Verweis, [string]$Spalte = 'Server', [string]$Grund = 'Abfrage nicht möglich') {
    foreach ($x in ($Befunde | Where-Object { $_.Id -match $IdMuster })) {
        $war = $x.Anzahl
        $zeilen = @($Namen | ForEach-Object { [pscustomobject][ordered]@{ $Spalte = $_; Feststellung = "Nicht geprüft - $Grund (siehe $Verweis)"; Details = '' } })
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
    param([string]$Name, [string]$Datei, [string]$Bezug, [string]$BezugName = 'Domäne', [System.Collections.IDictionary]$Umgebung,
        [System.Collections.IDictionary]$Abschnitte = @{}, [System.Collections.IDictionary]$Anhang = @{}, [string]$Fuss)
    Write-Host '  Bericht schreiben ...'
    $jetzt = Get-Date
    $ziel = $script:Ausgabe
    if (-not $ziel) { $ziel = Join-Path (Get-Location).Path ("{0}_{1}_{2:yyyy-MM-dd_HHmm}.html" -f $Datei, $Bezug, $jetzt) }
    $ziel = [System.IO.Path]::GetFullPath($ziel)
    $ordner = Split-Path $ziel -Parent
    if (-not (Test-Path $ordner)) { New-Item -ItemType Directory -Path $ordner -Force | Out-Null }

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
    [void]$h.Append("<!DOCTYPE html><html lang='de'><head><meta charset='utf-8'><title>$(Html $Name) $(Html $Bezug)</title><style>$css</style></head><body><div class='seite'>")
    [void]$h.Append("<h1>$(Html $Name)</h1><div class='meta'>$(Html $BezugName) <b>$(Html $Bezug)</b> · erstellt am $($jetzt.ToString('dd.MM.yyyy HH:mm')) von $(Html "$env:USERDOMAIN\$env:USERNAME") auf $(Html $env:COMPUTERNAME)</div>")
    [void]$h.Append("<div class='kacheln'>")
    foreach ($s in 'Hoch', 'Mittel', 'Niedrig', 'Info', 'OK') {
        $text = @{ Hoch = 'Befunde mit hoher Priorität'; Mittel = 'mit mittlerer Priorität'; Niedrig = 'mit niedriger Priorität'; Info = 'Hinweise und nicht geprüft'; OK = 'Prüfpunkte ohne Befund' }[$s]
        [void]$h.Append("<div class='kachel $s'><b>$($zahl[$s])</b><span>$text</span></div>")
    }
    [void]$h.Append("</div><h2>Umgebung</h2><table><tr><th>Eigenschaft</th><th>Wert</th></tr>")
    foreach ($k in $Umgebung.Keys) { [void]$h.Append("<tr><td>$(Html $k)</td><td>$(Html $Umgebung[$k])</td></tr>") }
    [void]$h.Append("</table>")

    [void]$h.Append("<h2>Übersicht der Prüfpunkte</h2><table><tr><th>Nr.</th><th>Bereich</th><th>Prüfpunkt</th><th>Treffer</th><th>Bewertung</th></tr>")
    foreach ($x in $Befunde) {
        [void]$h.Append("<tr><td>$($x.Id)</td><td>$(Html $x.Bereich)</td><td><a href='#$($x.Id)'>$(Html $x.Titel)</a></td><td>$($x.Anzahl)</td><td><span class='marke m-$($x.Stufe)'>$($x.Stufe)</span></td></tr>")
    }
    [void]$h.Append("</table>")

    foreach ($k in $Abschnitte.Keys) {
        [void]$h.Append("<h2>$(Html $k)</h2>")
        $inhalt = $Abschnitte[$k]
        if ($inhalt -is [string]) { [void]$h.Append($inhalt) }
        elseif (@($inhalt).Count) { [void]$h.Append(((Einheitlich $inhalt | ConvertTo-Html -Fragment) -join "`n")) }
        else { [void]$h.Append("<p class='klein'>Keine Einträge.</p>") }
    }

    [void]$h.Append("<h2>Befunde</h2>")
    $offen = @($Befunde | Where-Object { $_.Stufe -ne 'OK' } | Sort-Object { $rang[$_.Stufe] }, { IdText $_.Id }, { IdZahl $_.Id })
    foreach ($x in $offen) {
        [void]$h.Append("<div class='befund $($x.Stufe)' id='$($x.Id)'><h3><span class='marke m-$($x.Stufe)'>$($x.Stufe)</span> $($x.Id) · $(Html $x.Titel) <span class='klein'>($($x.Anzahl) Treffer)</span></h3>")
        [void]$h.Append("<p>$(Html $x.Erklaerung)</p><p class='emp'><b>Empfehlung:</b> $(Html $x.Empfehlung)</p>")
        [void]$h.Append(((Einheitlich $x.Objekte | ConvertTo-Html -Fragment) -join "`n"))
        [void]$h.Append("</div>")
    }
    if (-not $offen.Count) { [void]$h.Append("<p>Keine Auffälligkeiten gefunden.</p>") }
    $ok = @($Befunde | Where-Object Stufe -eq 'OK')
    if ($ok.Count) {
        [void]$h.Append("<h2>Ohne Befund</h2><table><tr><th>Nr.</th><th>Prüfpunkt</th></tr>")
        foreach ($x in $ok) { [void]$h.Append("<tr id='$($x.Id)'><td>$($x.Id)</td><td>$(Html $x.Titel)</td></tr>") }
        [void]$h.Append("</table>")
    }
    foreach ($k in $Anhang.Keys) { [void]$h.Append("<h2>$(Html $k)</h2><pre>$(Html $Anhang[$k])</pre>") }
    [void]$h.Append("<div class='fuss'>$(Html $Name) Version $script:Version · IT Admin Tools by MM · Das Skript hat ausschließlich gelesen und nichts verändert. $(Html $Fuss)</div>")
    [void]$h.Append("</div></body></html>")
    [System.IO.File]::WriteAllText($ziel, $h.ToString(), (New-Object System.Text.UTF8Encoding($true)))

    $basis = [System.IO.Path]::ChangeExtension($ziel, $null).TrimEnd('.')
    if ($script:Csv) {
        foreach ($x in ($Befunde | Where-Object { $_.Anzahl -gt 0 })) {
            Einheitlich $x.Objekte | Export-Csv -Path "${basis}_$($x.Id).csv" -NoTypeInformation -Delimiter ';' -Encoding UTF8
        }
    }
    Write-Host ''
    Write-Host ("Fertig: {0} hoch, {1} mittel, {2} niedrig, {3} ohne Befund." -f $zahl.Hoch, $zahl.Mittel, $zahl.Niedrig, $zahl.OK) -ForegroundColor Green
    Write-Host "Bericht: $ziel"
    if (-not $script:NichtOeffnen -and [Environment]::UserInteractive) { try { Start-Process $ziel } catch { } }
    $basis
}

function Zeile($server, $was, $details = '') { [pscustomobject]@{ Server = $server; Feststellung = $was; Details = $details } }
# Eine fehlgeschlagene Abfrage ist selbst eine Feststellung - sonst sähe der Prüfpunkt fälschlich sauber aus
function Fehlzeile($server, $fehler, $was = '') { Zeile $server ("Abfrage fehlgeschlagen - nicht geprüft" + $(if ($was) { " ($was)" })) (Kurz $fehler.Exception.Message) }
function Kurzname($n) { ("$n" -split '\.')[0].ToUpper() }

Write-Host 'DNS- und DHCP-Bericht - es wird nur gelesen, nichts verändert.' -ForegroundColor Cyan
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
    if (-not $modul) { $n1 += Zeile $env:COMPUTERNAME 'Modul "DnsServer" fehlt - DNS nicht geprüft' 'Auf einem DNS-Server starten oder RSAT-DNS-Server installieren' }
    else {
        Import-Module DnsServer
        if (-not $DnsServer) {
            try { $DnsServer = @(Resolve-DnsName -Name $dom.DNSRoot -Type NS -ErrorAction Stop | Where-Object { $_.Type -eq 'NS' } | ForEach-Object { $_.NameHost.TrimEnd('.') } | Sort-Object -Unique) }
            catch { $n1 += Fehlzeile $dom.DNSRoot $_ 'Namenserver der Domäne ermitteln' }
        }
        $zonenGesehen = @{}
        foreach ($srv in $DnsServer) {
            $name = Kurzname $srv
            Write-Host "  DNS-Server $name ..."
            try { $einst = Get-DnsServerScavenging -ComputerName $srv -ErrorAction Stop }
            catch { $n1 += Fehlzeile $name $_; continue }
            try { $dnsAdressen += @(Resolve-DnsName -Name $srv -Type A -ErrorAction Stop | Where-Object { $_.Type -eq 'A' } | ForEach-Object { $_.IPAddress }) } catch { }

            # --- Alterung auf dem Server
            if (-not $einst.ScavengingState) { $n2 += Zeile $name 'Automatisches Aufräumen veralteter Einträge ist ausgeschaltet' }
            elseif ($einst.LastScavengeTime -and $einst.LastScavengeTime -lt $jetzt.AddDays(-30)) { $n2 += Zeile $name 'Aufräumen eingeschaltet, aber seit über 30 Tagen nicht gelaufen' "Letzter Lauf: $(Datum $einst.LastScavengeTime)" }

            # --- Weiterleitungen
            $weiter = @()
            try {
                $fw = Get-DnsServerForwarder -ComputerName $srv -ErrorAction Stop
                $weiter = @($fw.IPAddress | ForEach-Object { "$_" } | Where-Object { $_ })
                foreach ($ip in $weiter) {
                    try { Resolve-DnsName -Name '.' -Type NS -Server $ip -DnsOnly -QuickTimeout -ErrorAction Stop | Out-Null }
                    catch {
                        # Antworten wie "Name nicht gefunden" oder "Serverfehler" zeigen, dass der Server erreichbar ist
                        if ($_.Exception.NativeErrorCode -notin 9002, 9003, 9501) { $n8 += Zeile $name "Weiterleitung $ip antwortet nicht" (Kurz $_.Exception.Message) }
                    }
                }
                if ($weiter.Count -eq 1) { $n8 += Zeile $name 'Nur eine Weiterleitung eingetragen' "Fällt $($weiter[0]) aus, verzögert sich die Namensauflösung nach außen" }
            } catch { $n8 += Fehlzeile $name $_ 'Weiterleitungen' }

            # --- Zonen
            try { $zonen = @(Get-DnsServerZone -ComputerName $srv -ErrorAction Stop | Where-Object { -not $_.IsAutoCreated -and $_.ZoneName -ne 'TrustAnchors' }) }
            catch { $n1 += Fehlzeile $name $_ 'Zonen'; continue }
            $dnsUebersicht += [pscustomobject][ordered]@{
                Server = $name; Zonen = $zonen.Count; 'Aufräumen' = JaNein $einst.ScavengingState
                'Letzter Aufräumlauf' = Datum $einst.LastScavengeTime; Weiterleitungen = $(if ($weiter.Count) { $weiter -join ', ' } else { 'keine (Stammhinweise)' })
            }
            if (@($zonen | Where-Object { $_.ZoneName -eq '.' }).Count) { $n11 += Zeile $name 'Der Server führt eine Stammzone "."' 'Er hält sich damit für die Wurzel des DNS und löst keine Namen im Internet auf' }
            if (-not @($zonen | Where-Object { $_.IsReverseLookupZone -and $_.ZoneType -eq 'Primary' }).Count) { $n10 += Zeile $name 'Keine Reverse-Lookupzone vorhanden' }

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
                if ("$($z.DynamicUpdate)" -eq 'NonsecureAndSecure') { $n5 += Zeile $name "Zone $($z.ZoneName) nimmt unsichere dynamische Updates an" }
                if ("$($z.SecureSecondaries)" -eq 'TransferAnyServer') { $n7 += Zeile $name "Zone $($z.ZoneName) darf an jeden Server übertragen werden" }
                if (-not $z.IsDsIntegrated) { $n6 += Zeile $name "Zone $($z.ZoneName) liegt nur als Datei auf diesem Server" 'Nicht im Active Directory gespeichert' }
                if ("$($z.DynamicUpdate)" -eq 'None') { continue }
                try {
                    $alter = Get-DnsServerZoneAging -Name $z.ZoneName -ComputerName $srv -ErrorAction Stop
                    if (-not $alter.AgingEnabled) { $n3 += Zeile $name "Zone $($z.ZoneName): Alterung ausgeschaltet" 'Veraltete dynamische Einträge werden nie entfernt' }
                } catch { $n3 += Fehlzeile $name $_ "Alterung der Zone $($z.ZoneName)" }
                if ($z.IsReverseLookupZone -or $z.ZoneName -like '_msdcs.*') { continue }
                try {
                    $eintraege = @(Get-DnsServerResourceRecord -ZoneName $z.ZoneName -ComputerName $srv -RRType A -ErrorAction Stop | Where-Object { $_.HostName -notin '@', 'DomainDnsZones', 'ForestDnsZones' })
                    $grenze = $jetzt.AddDays(-$VeraltetTage)
                    foreach ($e in ($eintraege | Where-Object { $_.Timestamp -and $_.Timestamp -lt $grenze } | Sort-Object Timestamp)) {
                        $n4 += Zeile $name "$($e.HostName).$($z.ZoneName) zuletzt aktualisiert am $(Datum $e.Timestamp)" "Adresse $($e.RecordData.IPv4Address)"
                    }
                    # Mehrere dynamisch eingetragene Namen auf derselben Adresse: fast immer ein Überbleibsel
                    foreach ($gr in ($eintraege | Where-Object Timestamp | Group-Object { "$($_.RecordData.IPv4Address)" } | Where-Object Count -gt 1)) {
                        $n9 += Zeile $name "Adresse $($gr.Name) ist für $($gr.Count) Namen eingetragen" (($gr.Group | ForEach-Object { $_.HostName }) -join ', ')
                    }
                } catch { $n4 += Fehlzeile $name $_ "Einträge der Zone $($z.ZoneName)" }
            }
        }
    }
    Befund 'N1' 'DNS' 'DNS-Server nicht abfragbar' 'Hoch' $n1 `
        'Der Server ist als Namenserver der Domäne eingetragen, lässt sich aber nicht abfragen. Für ihn wurde nichts geprüft.' `
        'Prüfen, ob der Server läuft, ob das Konto DNS verwalten darf und ob die Firewall die Fernverwaltung zulässt. Existiert der Server nicht mehr, seinen NS-Eintrag aus den Zonen entfernen.'
    Befund 'N3' 'DNS' 'Zonen ohne Alterung' 'Mittel' $n3 `
        'Das Aufräumen wirkt nur in Zonen, in denen die Alterung eingeschaltet ist. Geprüft werden Zonen mit dynamischen Updates.' `
        'In den Eigenschaften der Zone unter "Alterung" das Aufräumen veralteter Einträge aktivieren (Standardwerte: 7 Tage + 7 Tage).'
    Befund 'N5' 'DNS' 'Zonen mit unsicheren dynamischen Updates' 'Hoch' $n5 `
        'Jedes Gerät im Netz kann ohne Anmeldung Einträge anlegen oder überschreiben - auch den Namen eines Servers.' `
        'Zone im Active Directory speichern und dynamische Updates auf "Nur sichere" stellen.'
}

# ================================================================== DHCP
if (-not $OhneDhcp) {
    $h1 = @(); $h2 = @(); $h3 = @(); $h4 = @(); $h5 = @(); $h6 = @(); $h7 = @(); $h8 = @(); $h9 = @(); $h10 = @()
    $modul = [bool](Get-Module -ListAvailable -Name DhcpServer)
    if (-not $modul) { $h1 += Zeile $env:COMPUTERNAME 'Modul "DhcpServer" fehlt - DHCP nicht geprüft' 'Auf einem DHCP-Server starten oder RSAT-DHCP installieren (oder -OhneDhcp angeben)' }
    else {
        Import-Module DhcpServer
        if (-not $DhcpServer) {
            try { $DhcpServer = @(Get-DhcpServerInDC -ErrorAction Stop | ForEach-Object { $_.DnsName } | Sort-Object -Unique) }
            catch { $h1 += Fehlzeile $dom.DNSRoot $_ 'autorisierte DHCP-Server ermitteln' }
        }
        if (-not $dnsAdressen.Count) { $dnsAdressen = @($dcs | ForEach-Object { $_.IPv4Address }) }
        foreach ($srv in $DhcpServer) {
            $name = Kurzname $srv
            Write-Host "  DHCP-Server $name ..."
            try { $bereiche = @(Get-DhcpServerv4Scope -ComputerName $srv -ErrorAction Stop) }
            catch { $h1 += Fehlzeile $name $_; continue }
            $statistik = @{}
            try { Get-DhcpServerv4ScopeStatistics -ComputerName $srv -ErrorAction Stop | ForEach-Object { $statistik["$($_.ScopeId)"] = $_ } } catch { $h2 += Fehlzeile $name $_ 'Auslastung' }
            $schutz = @{}
            $failoverGelesen = $false
            try {
                foreach ($f in @(Get-DhcpServerv4Failover -ComputerName $srv -ErrorAction Stop)) {
                    foreach ($id in $f.ScopeId) { $schutz["$id"] = $f }
                    if ("$($f.State)" -ne 'Normal') { $h5 += Zeile $name "Failover-Beziehung '$($f.Name)' im Zustand $($f.State)" "Partner: $($f.PartnerServer), Modus: $($f.Mode)" }
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
                    'Lease-Dauer' = $(if ($b.LeaseDuration -eq [timespan]::MaxValue) { 'unbegrenzt' } else { "{0:N1} Tage" -f $b.LeaseDuration.TotalDays })
                    Belegt = $(if ($st) { $st.InUse } else { '?' }); Frei = $(if ($st) { $st.Free } else { '?' })
                    'Auslastung' = $(if ($st) { "{0:N0} %" -f $st.PercentageInUse } else { '?' }); Failover = $(if ($schutz[$id]) { $schutz[$id].Name } else { 'nein' })
                }
                if ("$($b.State)" -ne 'Active') { $h3 += Zeile $name "Bereich $id ($($b.Name)) ist deaktiviert"; continue }
                if ($st -and $st.PercentageInUse -ge $AuslastungProzent) { $h2 += Zeile $name ("Bereich $id ($($b.Name)) zu {0:N0} % belegt" -f $st.PercentageInUse) "$($st.InUse) belegt, $($st.Free) frei, $($st.Reserved) reserviert" }
                # Ließ sich Failover nicht lesen, steht das schon als Fehlzeile da - nicht zusätzlich jeden Bereich als ungeschützt melden
                if (-not $schutz[$id] -and $failoverGelesen) { $h4 += Zeile $name "Bereich $id ($($b.Name)) hat keinen Ausfallschutz (Failover)" }
                if ($b.LeaseDuration -eq [timespan]::MaxValue) { $h7 += Zeile $name "Bereich $id ($($b.Name)): Lease-Dauer unbegrenzt" }
                elseif ($b.LeaseDuration.TotalDays -gt 30) { $h7 += Zeile $name ("Bereich $id ($($b.Name)): Lease-Dauer {0:N0} Tage" -f $b.LeaseDuration.TotalDays) }

                # --- Optionen: Bereich hat Vorrang vor Server
                $opt = @{}
                foreach ($k in $serverOpt.Keys) { $opt[$k] = $serverOpt[$k] }
                try { Get-DhcpServerv4OptionValue -ComputerName $srv -ScopeId $b.ScopeId -All -ErrorAction Stop | ForEach-Object { $opt[[int]$_.OptionId] = $_.Value } }
                catch { $h6 += Fehlzeile $name $_ "Optionen des Bereichs $id"; continue }
                # Sind die Serveroptionen nicht lesbar, sagt ein fehlender Wert nichts aus
                if (-not $opt[3]) { if ($serverOptOk) { $h6 += Zeile $name "Bereich $id ($($b.Name)): Option 003 Router fehlt" 'Geräte erhalten kein Standardgateway' } }
                if (-not $opt[6]) { if ($serverOptOk) { $h6 += Zeile $name "Bereich $id ($($b.Name)): Option 006 DNS-Server fehlt" } }
                else {
                    $fremd = @($opt[6] | Where-Object { $_ -notin $dnsAdressen })
                    if ($fremd.Count) { $h6 += Zeile $name "Bereich $id ($($b.Name)): DNS-Server, der kein DNS-Server der Domäne ist" "Verteilt: $($opt[6] -join ', ') - fremd: $($fremd -join ', ')" }
                    if (@($opt[6]).Count -eq 1 -and $dnsAdressen.Count -gt 1) { $h6 += Zeile $name "Bereich $id ($($b.Name)): nur ein DNS-Server verteilt" "Verteilt: $($opt[6] -join ', ')" }
                }
                if ($opt[15] -and "$($opt[15])" -ne $dom.DNSRoot) { $h6 += Zeile $name "Bereich $id ($($b.Name)): Option 015 DNS-Domänenname weicht ab" "Verteilt: $($opt[15]), Domäne: $($dom.DNSRoot)" }

                try {
                    $schlecht = @(Get-DhcpServerv4Lease -ComputerName $srv -ScopeId $b.ScopeId -ErrorAction Stop | Where-Object { "$($_.AddressState)" -eq 'Declined' -or $_.HostName -eq 'BAD_ADDRESS' })
                    if ($schlecht.Count) { $h8 += Zeile $name "Bereich $id ($($b.Name)): $($schlecht.Count) Adressen als Konflikt markiert (BAD_ADDRESS)" (($schlecht | Select-Object -First 15 | ForEach-Object { "$($_.IPAddress)" }) -join ', ') }
                } catch { $h8 += Fehlzeile $name $_ "Leases des Bereichs $id" }
            }

            $zugang = ''
            try {
                $zug = Get-DhcpServerDnsCredential -ComputerName $srv -ErrorAction Stop
                $zugang = $zug.UserName
                if (-not $zugang -and $name -in $dcNamen) { $h9 += Zeile $name 'DHCP läuft auf einem Domänencontroller ohne eigenes Konto für DNS-Einträge' }
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
    Befund 'H1' 'DHCP' 'DHCP-Server nicht abfragbar' 'Hoch' $h1 `
        'Der Server ist im Active Directory als DHCP-Server autorisiert, lässt sich aber nicht abfragen. Für ihn wurde nichts geprüft. Ist kein Windows-DHCP-Server autorisiert (DHCP läuft z. B. auf Router oder Firewall), bleibt der DHCP-Teil leer.' `
        'Prüfen, ob der Server läuft und das Konto DHCP verwalten darf. Existiert der Server nicht mehr, die Autorisierung im Active Directory entfernen.'
    Befund 'H2' 'DHCP' "Bereiche mit mindestens $AuslastungProzent % Auslastung" 'Hoch' $h2 `
        'Ist ein Bereich voll, erhalten neue Geräte keine Adresse mehr - meist fällt das zuerst bei Besuchern und im WLAN auf.' `
        'Bereich vergrößern, Lease-Dauer verkürzen (z. B. 8 Stunden im Gäste-WLAN) oder ungenutzte Reservierungen entfernen.'
}

$umgebung = [ordered]@{
    'Domäne (NetBIOS)' = "$($dom.DNSRoot) ($($dom.NetBIOSName))"
    'Geprüfte DNS-Server' = $(if ($OhneDns) { 'übersprungen' } elseif ($DnsServer) { ($DnsServer | ForEach-Object { Kurzname $_ }) -join ', ' } else { 'keine' })
    'Geprüfte DHCP-Server' = $(if ($OhneDhcp) { 'übersprungen' } elseif ($DhcpServer) { ($DhcpServer | ForEach-Object { Kurzname $_ }) -join ', ' } else { 'keine im Active Directory autorisiert' })
    'Schwellen dieses Berichts' = "DNS-Einträge veraltet ab $VeraltetTage Tagen, DHCP-Auslastung ab $AuslastungProzent %"
}
$abschnitte = [ordered]@{}
if (-not $OhneDns) { $abschnitte['DNS-Server'] = $dnsUebersicht; $abschnitte['DNS-Zonen'] = $zonenUebersicht }
if (-not $OhneDhcp) { $abschnitte['DHCP-Server'] = $dhcpUebersicht; $abschnitte['DHCP-Bereiche'] = $bereichUebersicht }
BerichtSchreiben -Name 'DNS- und DHCP-Bericht Light' -Datei 'DNS-DHCP-Bericht' -Bezug $dom.DNSRoot -Umgebung $umgebung -Abschnitte $abschnitte `
    -Fuss 'Light-Version mit 5 von 21 Prüfpunkten der Vollversion (https://mueller86.gumroad.com/l/sthgh). Der Bericht zeigt Auffälligkeiten anhand fester Regeln zum Zeitpunkt des Laufs; er ersetzt keine laufende Überwachung und erhebt keinen Anspruch auf Vollständigkeit. Dieser Bericht enthält Servernamen und Adressen - bitte vertraulich behandeln.' | Out-Null
if ($PassThru) { $Befunde }
