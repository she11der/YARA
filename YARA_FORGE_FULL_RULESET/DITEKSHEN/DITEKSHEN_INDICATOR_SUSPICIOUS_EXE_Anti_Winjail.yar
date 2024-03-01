import "pe"
import "time"

rule DITEKSHEN_INDICATOR_SUSPICIOUS_EXE_Anti_Winjail : FILE
{
	meta:
		description = "Detects executables potentially checking for WinJail sandbox window"
		author = "ditekSHen"
		id = "f3a3d099-7659-50aa-8dca-3a2b1c18c3b5"
		date = "2024-02-22"
		modified = "2024-02-22"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_suspicious.yar#L1512-L1520"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "ae8080dad4481b6a2e295c29d3ed24e86da83575e1a5aeda8b1317e6caa74707"
		score = 40
		quality = 45
		tags = "FILE"
		importance = 20

	strings:
		$s1 = "Afx:400000:0" fullword ascii wide

	condition:
		uint16(0)==0x5a4d and all of them
}
