rule SIGNATURE_BASE_Poisonivy_Sample_APT_2 : FILE
{
	meta:
		description = "Detects a PoisonIvy Malware"
		author = "Florian Roth (Nextron Systems)"
		id = "4d64ccd2-add8-5749-8178-f2c5336e1495"
		date = "2015-06-03"
		modified = "2023-12-05"
		reference = "VT Analysis"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_poisonivy.yar#L24-L58"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "333f956bf3d5fc9b32183e8939d135bc0fcc5770"
		logic_hash = "58d62278d776c9f7c3ae0815aa4b248f85c5fc648405b8d1ba2b8eb2847e1e88"
		score = 70
		quality = 83
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "pidll.dll" fullword ascii
		$s1 = "sens32.dll" fullword wide
		$s2 = "9.0.1.56" fullword wide
		$s3 = "FileDescription" fullword wide
		$s4 = "OriginalFilename" fullword wide
		$s5 = "ZwSetInformationProcess" fullword ascii
		$s6 = "\"%=%14=" fullword ascii
		$s7 = "091A1G1R1_1g1u1z1" fullword ascii
		$s8 = "gHsMZz" fullword ascii
		$s9 = "Microsoft Media Device Service Provider" fullword wide
		$s10 = "Copyright (C) Microsoft Corp." fullword wide
		$s11 = "MFC42.DLL" fullword ascii
		$s12 = "MSVCRT.dll" fullword ascii
		$s13 = "SpecialBuild" fullword wide
		$s14 = "PrivateBuild" fullword wide
		$s15 = "Comments" fullword wide
		$s16 = "040904b0" fullword wide
		$s17 = "LegalTrademarks" fullword wide
		$s18 = "CreateThread" fullword ascii
		$s19 = "ntdll.dll" fullword ascii
		$s20 = "_adjust_fdiv" ascii

	condition:
		uint16(0)==0x5a4d and filesize <47KB and all of them
}
