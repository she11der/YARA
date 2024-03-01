import "pe"
import "time"

rule DITEKSHEN_INDICATOR_SUSPICIOUS_PWS_Capturebrowserplugins
{
	meta:
		description = "Detects PowerShell script with browser plugins capture capability"
		author = "ditekSHen"
		id = "9b1bb195-6e32-5f93-ba70-efcb21b26bb0"
		date = "2024-02-22"
		modified = "2024-02-22"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_suspicious.yar#L2379-L2392"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "ac7be8663507e96ecb224f7f09f9092069eab5967598e33c107fa341de86bc77"
		score = 40
		quality = 45
		tags = ""
		importance = 20

	strings:
		$s1 = "$env:APPDATA +" ascii nocase
		$s2 = "[\\w-]{24}\\.[\\w-]{6}\\.[\\w-]{27}|mfa\\.[\\w-]{84}" ascii nocase
		$s3 = "\\leveldb" ascii nocase
		$o1 = ".Match(" ascii nocase
		$o2 = ".Contains(" ascii nocase
		$o3 = ".Add(" ascii nocase

	condition:
		2 of ($s*) and 2 of ($o*)
}
