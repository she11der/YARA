import "pe"

rule SIGNATURE_BASE_Equationgroup_Processoptions_Lp : FILE
{
	meta:
		description = "EquationGroup Malware - file ProcessOptions_Lp.dll"
		author = "Florian Roth (Nextron Systems)"
		id = "5ccb9751-fbcc-538c-8d55-dfc495067ce5"
		date = "2017-01-13"
		modified = "2023-12-05"
		reference = "https://goo.gl/tcSoiJ"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_eqgrp.yar#L1870-L1883"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "cc9cd566f57d28ccea6d53d2eba71187f01cdf6e140771cace33349f6439461d"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "31d86f77137f0b3697af03dd28d6552258314cecd3c1d9dc18fcf609eb24229a"

	strings:
		$s1 = "Invalid parameter received by implant" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <300KB and all of them )
}
