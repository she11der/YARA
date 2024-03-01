import "pe"
import "time"

rule DITEKSHEN_INDICATOR_SUSPICIOUS_EXE_Uacbypass_Cleanmgr : FILE
{
	meta:
		description = "detects Windows exceutables potentially bypassing UAC using cleanmgr.exe"
		author = "ditekSHen"
		id = "cebbe22d-d54d-5a1e-978a-37ddd96133b7"
		date = "2024-02-22"
		modified = "2024-02-22"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_suspicious.yar#L79-L88"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "9b9e2789bee4f3b54384dabde028a7b6e70b3e0d66090d5141145a72df515db4"
		score = 40
		quality = 41
		tags = "FILE"
		importance = 20

	strings:
		$s1 = "\\Enviroment\\windir" ascii wide nocase
		$s2 = "\\system32\\cleanmgr.exe" ascii wide nocase

	condition:
		uint16(0)==0x5a4d and all of them
}
