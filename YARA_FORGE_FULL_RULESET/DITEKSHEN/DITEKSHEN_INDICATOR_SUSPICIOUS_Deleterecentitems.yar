import "pe"
import "time"

rule DITEKSHEN_INDICATOR_SUSPICIOUS_Deleterecentitems : FILE
{
	meta:
		description = "Detects executables embedding anti-forensic artifacts of deleting Windows Recent Items"
		author = "ditekSHen"
		id = "58a14ad6-8f32-54d8-b343-88629af8810b"
		date = "2024-02-22"
		modified = "2024-02-22"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_suspicious.yar#L2308-L2319"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "01efada47910a345e7bde4e9295754aefec38355193f45c4630f55050d835cd9"
		score = 40
		quality = 37
		tags = "FILE"
		importance = 20

	strings:
		$s1 = "del C:\\Windows\\AppCompat\\Programs\\RecentFileCache.bcf" ascii wide nocase
		$s2 = "del /F /Q %APPDATA%\\Microsoft\\Windows\\Recent\\*" ascii wide nocase
		$s3 = "del /F /Q %APPDATA%\\Microsoft\\Windows\\Recent\\CustomDestinations\\*" ascii wide nocase
		$s4 = "del /F /Q %APPDATA%\\Microsoft\\Windows\\Recent\\AutomaticDestinations\\*" ascii wide nocase

	condition:
		uint16(0)==0x5a4d and 2 of them
}
