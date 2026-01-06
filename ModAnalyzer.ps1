Clear-Host
$Logo = @"
 _____      _        _____ _                
|  ___|_ _| | _____|_   _(_)_ __ ___   ___ 
| |_ / _` | |/ / _ \ | | | | '_ ` _ \ / _ \
|  _| (_| |   <  __/ | | | | | | | | |  __/
|_|  \__,_|_|\_\___| |_| |_|_| |_| |_|\___|
"@
Write-Host $Logo -ForegroundColor Cyan
Write-Host "Minecraft Mod Security Scanner" -ForegroundColor Yellow
Write-Host ""

$defaultMods = "$env:USERPROFILE\AppData\Roaming\.minecraft\mods"
$mods = $defaultMods

if (-not (Test-Path $mods -PathType Container)) {
    Write-Host "Папка mods не найдена! Путь: $mods" -ForegroundColor Red
    exit 1
}

Write-Host "Найден путь: $mods" -ForegroundColor White
Write-Host ""

function Get-SHA1 {
    param ([string]$filePath)
    return (Get-FileHash -Path $filePath -Algorithm SHA1).Hash
}

function Get-ZoneIdentifier {
    param ([string]$filePath)
	$ads = Get-Content -Raw -Stream Zone.Identifier $filePath -ErrorAction SilentlyContinue
	if ($ads -match "HostUrl=(.+)") {
		return $matches[1]
	}
	return $null
}

function Fetch-Modrinth {
    param ([string]$hash)
    try {
        $response = Invoke-RestMethod -Uri "https://api.modrinth.com/v2/version_file/$hash" -Method Get -UseBasicParsing -ErrorAction Stop
		if ($response.project_id) {
            $projectResponse = "https://api.modrinth.com/v2/project/$($response.project_id)"
            $projectData = Invoke-RestMethod -Uri $projectResponse -Method Get -UseBasicParsing -ErrorAction Stop
            return @{ Name = $projectData.title; Slug = $projectData.slug }
        }
    } catch {}
	return $null
}

function Fetch-Megabase {
    param ([string]$hash)
    try {
        $response = Invoke-RestMethod -Uri "https://megabase.vercel.app/api/query?hash=$hash" -Method Get -UseBasicParsing -ErrorAction Stop
		if (-not $response.error) {
			return $response.data
		}
    } catch {}
	return $null
}

# Общие подозрительные строки
$suspiciousStrings = @(
  "AimAssist", "AnchorTweaks", "AutoAnchor", "AutoCrystal", "AutoDoubleHand",
  "AutoHitCrystal", "AutoPot", "AutoTotem", "AutoArmor", "InventoryTotem",
  "Hitboxes", "JumpReset", "LegitTotem", "PingSpoof", "SelfDestruct",
  "ShieldBreaker", "TriggerBot", "Velocity", "AxeSpam", "WebMacro",
  "FastPlace", "areyoufuckingdump", "me.didyoumuch.Native", "stubborn.website",
  "Vsevolod", "(Lbrx;DDD)VI", "Lbrx;DDD)VL", "(Lbrx;DDD)Vg", ".crash",
  "bushroot", "imapDef", "imoRs", "BaoBab", "waohitbox", "ogohiti",
  "MagicThe", "reach:", "#size", "neathitbox", "Derick1337"
)

# Конкретные читерские строки для поиска в .class файлах
$cheatClassStrings = @(
  "KillAura",
  "attackEntity()",
  "func_174813_aQ()",
  "method_5829()",
  "func_70032_d()",
  "method_5739()",
  "func_70685_l()",
  "method_5779()",
  "ESP"
)

function Check-Jar-File-Binary {
    param ([string]$jarPath)
    
    try {
        $foundStrings = [System.Collections.Generic.List[string]]::new()
        $fileBytes = [System.IO.File]::ReadAllBytes($jarPath)
        $fileText = [System.Text.Encoding]::Default.GetString($fileBytes)
        
        foreach ($string in $suspiciousStrings) {
            if ($fileText.Contains($string)) {
                $foundStrings.Add($string)
            }
        }
        
        return $foundStrings
    } catch {
        return [System.Collections.Generic.List[string]]::new()
    }
}

function Scan-Class-Files {
    param ([string]$jarPath)
    
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $jarFile = [System.IO.Compression.ZipFile]::OpenRead($jarPath)
        
        $foundCheatStrings = [System.Collections.Generic.List[string]]::new()
        $scannedClassCount = 0
        
        foreach ($entry in $jarFile.Entries) {
            if ($entry.Name.EndsWith(".class")) {
                $scannedClassCount++
                
                try {
                    $reader = New-Object System.IO.StreamReader $entry.Open()
                    $content = $reader.ReadToEnd()
                    $reader.Close()
                    
                    foreach ($cheatString in $cheatClassStrings) {
                        if ($content.Contains($cheatString)) {
                            $foundCheatStrings.Add("$cheatString (в $($entry.Name))")
                        }
                    }
                } catch {
                    # Пропускаем ошибки чтения
                }
            }
        }
        
        $jarFile.Dispose()
        
        return @{
            FoundStrings = $foundCheatStrings
            ScannedClasses = $scannedClassCount
        }
    } catch {
        return @{
            FoundStrings = [System.Collections.Generic.List[string]]::new()
            ScannedClasses = 0
        }
    }
}

$verifiedMods = @()
$unknownMods = @()
$suspiciousMods = @()  # Подозрительные моды
$cheatMods = @()       # Чит-моды (найдены конкретные читы в классах)
$jarFiles = Get-ChildItem -Path $mods -Filter *.jar

if ($jarFiles.Count -eq 0) {
    Write-Host "В папке mods не найдено файлов .jar!" -ForegroundColor Red
    exit 1
}

Write-Host "Сканирование модов..." -ForegroundColor Cyan
Write-Host ""

$scannedCount = 0
foreach ($file in $jarFiles) {
    $scannedCount++
    Write-Host "  Сканирование: $($file.Name) ($scannedCount/$($jarFiles.Count))" -ForegroundColor Gray
    
	$hash = Get-SHA1 -filePath $file.FullName
	
    $modDataModrinth = Fetch-Modrinth -hash $hash
    if ($modDataModrinth -and $modDataModrinth.Slug) {
		$verifiedMods += [PSCustomObject]@{ 
            ModName = $modDataModrinth.Name
            FileName = $file.Name 
        }
		continue
    }
	
	$modDataMegabase = Fetch-Megabase -hash $hash
	if ($modDataMegabase -and $modDataMegabase.name) {
		$verifiedMods += [PSCustomObject]@{ 
            ModName = $modDataMegabase.Name
            FileName = $file.Name 
        }
		continue
	}
	
	$zoneId = Get-ZoneIdentifier $file.FullName
	$unknownMods += [PSCustomObject]@{ 
        FileName = $file.Name
        FilePath = $file.FullName
        ZoneId = $zoneId 
    }
}

Write-Host ""

if ($unknownMods.Count -gt 0) {
	Write-Host "Анализ неизвестных модов..." -ForegroundColor Cyan
    Write-Host ""
    
    $suspiciousModsTemp = @()
    $remainingUnknownMods = @()
    
	foreach ($mod in $unknownMods) {
        Write-Host "  Проверка: $($mod.FileName)" -ForegroundColor Gray
        
        # 1. Быстрый бинарный поиск общих подозрительных строк
		$foundSuspicious = Check-Jar-File-Binary -jarPath $mod.FilePath
		
		if ($foundSuspicious.Count -gt 0) {
            # 2. Если найдены подозрительные строки - углубленное сканирование классов
            Write-Host "    Найдены подозрительные строки, сканирование классов..." -ForegroundColor Yellow
            $classScanResult = Scan-Class-Files -jarPath $mod.FilePath
            
            if ($classScanResult.FoundStrings.Count -gt 0) {
                # Найдены конкретные читы в классах - ЧИТ-МОД
                $cheatMods += [PSCustomObject]@{ 
                    FileName = $mod.FileName
                    SuspiciousStrings = ($foundSuspicious -join ', ')
                    CheatStrings = ($classScanResult.FoundStrings -join '; ')
                    ClassesScanned = $classScanResult.ScannedClasses
                }
                Write-Host "    Обнаружен чит-мод!" -ForegroundColor Red
            } else {
                # Только подозрительные строки, но не читы в классах - ПОДОЗРИТЕЛЬНЫЙ МОД
                $suspiciousModsTemp += [PSCustomObject]@{ 
                    FileName = $mod.FileName
                    StringsFound = ($foundSuspicious -join ', ')
                    ClassesScanned = $classScanResult.ScannedClasses
                }
                Write-Host "    Подозрительный мод" -ForegroundColor DarkYellow
            }
		} else {
            # Нет подозрительных строк вообще
            $remainingUnknownMods += $mod
            Write-Host "    Без подозрений" -ForegroundColor Gray
        }
	}
    
    $unknownMods = $remainingUnknownMods
    $suspiciousMods = $suspiciousModsTemp
    
    Write-Host ""
}

Write-Host "=" * 60 -ForegroundColor DarkGray
Write-Host "РЕЗУЛЬТАТЫ СКАНА" -ForegroundColor Cyan
Write-Host "=" * 60 -ForegroundColor DarkGray
Write-Host ""

if ($verifiedMods.Count -gt 0) {
	Write-Host "{ ПРОВЕРЕННЫЕ МОДЫ ($($verifiedMods.Count)) }" -ForegroundColor Green
    Write-Host "-" * 40 -ForegroundColor DarkGray
	foreach ($mod in $verifiedMods) {
		Write-Host "  ✓ $($mod.ModName)" -ForegroundColor Green
        Write-Host "    Файл: $($mod.FileName)" -ForegroundColor DarkGray
	}
	Write-Host ""
}

if ($unknownMods.Count -gt 0) {
	Write-Host "{ НЕИЗВЕСТНЫЕ МОДЫ ($($unknownMods.Count)) }" -ForegroundColor Gray
    Write-Host "-" * 40 -ForegroundColor DarkGray
	foreach ($mod in $unknownMods) {
        if ($mod.ZoneId) {
		    Write-Host "  ? $($mod.FileName)" -ForegroundColor Gray
            Write-Host "    Источник: $($mod.ZoneId)" -ForegroundColor DarkGray
        } else {
		    Write-Host "  ? $($mod.FileName)" -ForegroundColor Gray
        }
	}
	Write-Host ""
}

if ($suspiciousMods.Count -gt 0) {
	Write-Host "{ ПОДОЗРИТЕЛЬНЫЕ МОДЫ ($($suspiciousMods.Count)) }" -ForegroundColor Yellow
    Write-Host "-" * 40 -ForegroundColor DarkGray
	foreach ($mod in $suspiciousMods) {
		Write-Host "  ⚠ $($mod.FileName)" -ForegroundColor Yellow
		Write-Host "    Строки: $($mod.StringsFound)" -ForegroundColor DarkYellow
        Write-Host "    Проверено классов: $($mod.ClassesScanned)" -ForegroundColor DarkGray
	}
	Write-Host ""
}

if ($cheatMods.Count -gt 0) {
	Write-Host "{ ОПАСНОСТЬ: ЧИТ-МОДЫ ($($cheatMods.Count)) }" -ForegroundColor Red -BackgroundColor Black
    Write-Host "-" * 40 -ForegroundColor DarkGray
	foreach ($mod in $cheatMods) {
		Write-Host "  ☠ $($mod.FileName)" -ForegroundColor Red
		Write-Host "    Подозрительные строки: $($mod.SuspiciousStrings)" -ForegroundColor DarkYellow
        Write-Host "    Найденные читы: $($mod.CheatStrings)" -ForegroundColor Magenta
        Write-Host "    Проверено классов: $($mod.ClassesScanned)" -ForegroundColor DarkGray
	}
	Write-Host ""
}

Write-Host "=" * 60 -ForegroundColor DarkGray
Write-Host ""

Write-Host "ФИНАЛЬНАЯ СТАТИСТИКА:" -ForegroundColor Cyan
Write-Host "  Всего модов:      $($jarFiles.Count)" -ForegroundColor White
Write-Host "  Проверенные:      $($verifiedMods.Count)" -ForegroundColor Green
Write-Host "  Неизвестные:      $($unknownMods.Count)" -ForegroundColor Gray
Write-Host "  Подозрительные:   $($suspiciousMods.Count)" -ForegroundColor Yellow
Write-Host "  Чит-моды:         $($cheatMods.Count)" -ForegroundColor Red
Write-Host ""

Write-Host "Сканирование завершено!" -ForegroundColor Green
if ($cheatMods.Count -gt 0) {
    Write-Host "ВНИМАНИЕ: Обнаружены чит-моды! Рекомендуется удалить их." -ForegroundColor Red -BackgroundColor Black
} elseif ($suspiciousMods.Count -gt 0) {
    Write-Host "Предупреждение: Есть подозрительные моды. Рекомендуется проверить." -ForegroundColor Yellow
} else {
    Write-Host "Все моды безопасны или проверены." -ForegroundColor Green
}
Write-Host ""
