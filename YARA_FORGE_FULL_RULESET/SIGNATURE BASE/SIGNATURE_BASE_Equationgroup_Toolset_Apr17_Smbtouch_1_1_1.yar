rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17_Smbtouch_1_1_1 : FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "225799cf-4d1b-54f8-8b76-b9ee1db80ce7"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp_apr17.yar#L1653-L1666"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "b5eb9d45dfc47470236923a5b8174bc17733e4333db6f8bbe63c4f4bc913cf26"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "108243f61c53f00f8f1adcf67c387a8833f1a2149f063dd9ef29205c90a3c30a"

	strings:
		$x1 = "[+] Target is vulnerable to %d exploit%s" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <400KB and all of them )
}
