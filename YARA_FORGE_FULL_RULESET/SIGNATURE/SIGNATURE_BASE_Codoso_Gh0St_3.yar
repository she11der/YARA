rule SIGNATURE_BASE_Codoso_Gh0St_3 : FILE
{
	meta:
		description = "Detects Codoso APT Gh0st Malware"
		author = "Florian Roth (Nextron Systems)"
		id = "55fb17c5-ee11-55be-9af3-e9fe8d6160b5"
		date = "2016-01-30"
		modified = "2023-12-05"
		reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_codoso.yar#L130-L151"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "bf52ca4d4077ae7e840cf6cd11fdec0bb5be890ddd5687af5cfa581c8c015fcd"
		logic_hash = "e24d434d8f08b83f8e4b1f4aa75a84a040e4f56cdbd9a58ff49c463437e78c24"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$x1 = "RunMeByDLL32" fullword ascii
		$s1 = "svchost.dll" fullword wide
		$s2 = "server.dll" fullword ascii
		$s3 = "Copyright ? 2008" fullword wide
		$s4 = "testsupdate33" fullword ascii
		$s5 = "Device Protect Application" fullword wide
		$s6 = "MSVCP60.DLL" fullword ascii
		$s7 = "mail-news.eicp.net" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <195KB and $x1 or 4 of them
}
