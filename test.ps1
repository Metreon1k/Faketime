# Запускать от Администратора

$ErrorActionPreference = "SilentlyContinue"



# Твои стринги (я добавил обработку твоей строки с ! и !0!)

$sigs = @(
    "!2023/07/03:22:01:11!0!",
    "2023/05/09:19 10 04",
    "2024/04/05",
    "2021/11/29:17:36:29",
    "2022/07/06:20:23:42",
    "2024/08/14:18:46:25",
    "2023/06/06:06:27:09",
    "2024/03/15:02 10 26",
    "2024/05/31:21:46:54"
)



$pd64 = "$env:TEMP\procdump64.exe"

$dumpFile = "$env:TEMP\dps_final.dmp"



if (!(Test-Path $pd64)) {

    Invoke-WebRequest -Uri "https://live.sysinternals.com/procdump64.exe" -OutFile $pd64 -UseBasicParsing

}



$pid = (Get-WmiObject Win32_Service | Where-Object { $_.Name -eq "DPS" }).ProcessId

if (!$pid) { Write-Host "[-] DPS не найден" -ForegroundColor Red; exit }



Write-Host "[>>>] Дамп DPS (PID: $pid)..." -ForegroundColor Cyan

& $pd64 -ma $pid $dumpFile -accepteula -nobanner



if (!(Test-Path $dumpFile)) { Write-Host "[-] Дамп не создался" -ForegroundColor Red; exit }



# Читаем дамп как массив байтов

$bytes = [System.IO.File]::ReadAllBytes($dumpFile)



# Декодируем в разные форматы для поиска

$methods = @{

    "Unicode" = [System.Text.Encoding]::Unicode.GetString($bytes)

    "ASCII"   = [System.Text.Encoding]::ASCII.GetString($bytes)

    "UTF8"    = [System.Text.Encoding]::UTF8.GetString($bytes)

}



Write-Host "[*] Поиск сигнатур..." -ForegroundColor Gray



foreach ($s in $sigs) {

    $found = $false

    # Убираем лишние ! и !0! для поиска самого тела даты, если оно там есть

    $cleanSig = $s.Trim('!')

    if ($cleanSig.EndsWith("!0!")) { $cleanSig = $cleanSig.Replace("!0!", "") }



    foreach ($method in $methods.Keys) {

        if ($methods[$method].Contains($cleanSig)) {

            Write-Host "[!!!] ДЕТЕКТ: $cleanSig (Найдено в кодировке: $method)" -ForegroundColor Red -BackgroundColor Black

            $found = $true

            break

        }

    }

}



Remove-Item $dumpFile -Force

Write-Host "`n[+] Проверка завершена." -ForegroundColor Cyan
