import "pe"
import "time"

rule DITEKSHEN_INDICATOR_SUSPICIOUS_EXE_Anti_Oldcopypaste : FILE
{
	meta:
		description = "Detects executables potentially checking for WinJail sandbox window"
		author = "ditekSHen"
		id = "10a70ad3-c37e-5522-ae3f-3f85f89f9394"
		date = "2024-02-22"
		modified = "2024-02-22"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_suspicious.yar#L1522-L1541"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "084a1613eaf1df4cd54c44e4389b9edc1c44b4b947a8c4416cb7cbdabc186747"
		score = 40
		quality = 45
		tags = "FILE"
		importance = 20

	strings:
		$s1 = "This file can't run into Virtual Machines" wide
		$s2 = "This file can't run into Sandboxies" wide
		$s3 = "This file can't run into RDP Servers" wide
		$s4 = "Run without emulation" wide
		$s5 = "Run using valid operating system" wide
		$v1 = "SbieDll.dll" fullword wide
		$v2 = "USER" fullword wide
		$v3 = "SANDBOX" fullword wide
		$v4 = "VIRUS" fullword wide
		$v5 = "MALWARE" fullword wide
		$v6 = "SCHMIDTI" fullword wide
		$v7 = "CURRENTUSER" fullword wide

	condition:
		uint16(0)==0x5a4d and (3 of ($s*) or all of ($v*))
}
