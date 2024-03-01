rule SIGNATURE_BASE_Furtim_Nativedll : FILE
{
	meta:
		description = "Detects Furtim malware - file native.dll"
		author = "Florian Roth (Nextron Systems)"
		id = "4639b637-55d3-5591-9278-5a21de23ac72"
		date = "2016-06-13"
		modified = "2023-12-05"
		reference = "MISP 3971"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_furtim.yar#L8-L25"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "f9673cdd1e8e38f98b9625291a03011d5cfce78c689eab491ff189c4e039e1ef"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "4f39d3e70ed1278d5fa83ed9f148ca92383ec662ac34635f7e56cc42eeaee948"

	strings:
		$s1 = "FqkVpTvBwTrhPFjfFF6ZQRK44hHl26" fullword ascii
		$op0 = { e0 b3 42 00 c7 84 24 ac }
		$op1 = { a1 e0 79 44 00 56 ff 90 10 01 00 00 a1 e0 79 44 }
		$op2 = { bf d0 25 44 00 57 89 4d f0 ff 90 d4 02 00 00 59 }

	condition:
		uint16(0)==0x5a4d and filesize <900KB and $s1 or all of ($op*)
}
