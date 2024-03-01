import "pe"
import "time"

rule DITEKSHEN_INDICATOR_SUSPICIOUS_EXE_Uacbypass_Envvarscheduledtasks
{
	meta:
		description = "detects Windows exceutables potentially bypassing UAC (ab)using Environment Variables in Scheduled Tasks"
		author = "ditekSHen"
		id = "14244310-e524-54bf-8822-9b953378bb75"
		date = "2024-02-22"
		modified = "2024-02-22"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_suspicious.yar#L1068-L1079"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "dacca794aefd66526535a87c8890c0ad65550ff88bc0242f05c84c9452a31fe2"
		score = 40
		quality = 45
		tags = ""
		importance = 20

	strings:
		$s1 = "\\Microsoft\\Windows\\DiskCleanup\\SilentCleanup" ascii wide
		$s2 = "\\Environment" ascii wide
		$s3 = "schtasks" ascii wide
		$s4 = "/v windir" ascii wide

	condition:
		all of them
}
