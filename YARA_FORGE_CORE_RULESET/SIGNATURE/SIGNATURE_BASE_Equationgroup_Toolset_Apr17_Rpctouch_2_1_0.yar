rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17_Rpctouch_2_1_0 : FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "0691768b-ca98-5722-8468-737c4966d54d"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_eqgrp_apr17.yar#L1700-L1714"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "3ea1f30c0a2c91cc9ca2eec8eaab167c83f4f52c2732d03d1e7fb99e63986662"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "7fe4c3cedfc98a3e994ca60579f91b8b88bf5ae8cf669baa0928508642c5a887"

	strings:
		$x1 = "[*] Failed to detect OS / Service Pack on %s:%d" fullword ascii
		$x2 = "[*] SMB String: %s (%s)" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <80KB and 1 of them )
}
