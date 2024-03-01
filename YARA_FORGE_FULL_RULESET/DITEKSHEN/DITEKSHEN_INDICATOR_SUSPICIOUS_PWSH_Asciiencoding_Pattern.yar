import "pe"
import "time"

rule DITEKSHEN_INDICATOR_SUSPICIOUS_PWSH_Asciiencoding_Pattern : FILE
{
	meta:
		description = "Detects PowerShell scripts containing ASCII encoded files"
		author = "ditekSHen"
		id = "df96d801-1a14-58af-b245-3a4a6ccf22c6"
		date = "2024-02-22"
		modified = "2024-02-22"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_suspicious.yar#L710-L724"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "037ce50a6c6d2bf25163e658c5a8c18950715a52fcdf47162fcd288306acbf9c"
		score = 40
		quality = 45
		tags = "FILE"
		importance = 20

	strings:
		$enc1 = "[char[]]([char]97..[char]122)" ascii
		$enc2 = "[char[]]([char]65..[char]90)" ascii
		$s1 = ".DownloadData($" ascii
		$s2 = "[Net.SecurityProtocolType]::TLS12" ascii
		$s3 = "::WriteAllBytes($" ascii
		$s4 = "::FromBase64String($" ascii
		$s5 = "Get-Random" ascii

	condition:
		1 of ($enc*) and 4 of ($s*) and filesize <2500KB
}
