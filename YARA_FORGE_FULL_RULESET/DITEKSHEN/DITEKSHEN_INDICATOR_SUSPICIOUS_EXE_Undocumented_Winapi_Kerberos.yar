import "pe"
import "time"

rule DITEKSHEN_INDICATOR_SUSPICIOUS_EXE_Undocumented_Winapi_Kerberos : FILE
{
	meta:
		description = "Detects executables referencing undocumented kerberos Windows APIs and obsereved in malware"
		author = "ditekSHen"
		id = "1eb7faab-66b8-5d98-b6a8-75a078c2f6f8"
		date = "2024-02-22"
		modified = "2024-02-22"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_suspicious.yar#L2052-L2066"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "19f22dcbc63723624d92be22cd69dcbab03a0b46299d43bc50ba73c79e573596"
		score = 40
		quality = 35
		tags = "FILE"
		importance = 20

	strings:
		$kdc1 = "KdcVerifyEncryptedTimeStamp" ascii wide nocase
		$kdc2 = "KerbHashPasswordEx3" ascii wide nocase
		$kdc3 = "KerbFreeKey" ascii wide nocase

	condition:
		uint16(0)==0x5a4d and all of ($kdc*)
}
