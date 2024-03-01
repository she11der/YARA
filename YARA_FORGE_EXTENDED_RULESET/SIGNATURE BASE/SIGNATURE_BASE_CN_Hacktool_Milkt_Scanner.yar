import "pe"

rule SIGNATURE_BASE_CN_Hacktool_Milkt_Scanner
{
	meta:
		description = "Detects a chinese Portscanner named MilkT"
		author = "Florian Roth (Nextron Systems)"
		id = "aa83c983-25c2-5051-88a1-fbc70d947d6e"
		date = "2014-12-10"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-hacktools.yar#L683-L701"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "707cbd625b5694b710d01622a053e60828da7f70b38e43012d04364137583fe9"
		score = 60
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "Bf **************" ascii fullword
		$s1 = "forming Time: %d/" ascii
		$s2 = "KERNEL32.DLL" ascii fullword
		$s3 = "CRTDLL.DLL" ascii fullword
		$s4 = "WS2_32.DLL" ascii fullword
		$s5 = "GetProcAddress" ascii fullword
		$s6 = "atoi" ascii fullword

	condition:
		all of them
}
