import "pe"
import "time"

rule DITEKSHEN_INDICATOR_SUSPICIOUS_EXE_Dotnetprochook : FILE
{
	meta:
		description = "Detects executables with potential process hoocking"
		author = "ditekSHen"
		id = "1c32c7ee-0ac6-50ae-892e-73f46902115d"
		date = "2024-02-22"
		modified = "2024-02-22"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_suspicious.yar#L1278-L1289"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "e01147886444f8080b7cf7b423dc70b4b08fae6b88a8875eb075530fdb9f7909"
		score = 40
		quality = 45
		tags = "FILE"
		importance = 20

	strings:
		$s1 = "UnHook" fullword ascii
		$s2 = "SetHook" fullword ascii
		$s3 = "CallNextHook" fullword ascii
		$s4 = "_hook" fullword ascii

	condition:
		uint16(0)==0x5a4d and all of them
}
