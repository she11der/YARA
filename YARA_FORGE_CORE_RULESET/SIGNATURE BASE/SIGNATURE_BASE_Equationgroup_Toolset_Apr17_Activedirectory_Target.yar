rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17_Activedirectory_Target : FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "1069cabe-7c09-522f-ad3f-05651490b921"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_eqgrp_apr17.yar#L3113-L3127"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "0dee634fe81870b21531046be512e9e54b127207c1910ca5ce5dfab63b1d0603"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "33c1b7fdee7c70604be1e7baa9eea231164e62d5d5090ce7f807f43229fe5c36"

	strings:
		$s1 = "(&(objectCategory=person)(objectClass=user)(cn=" fullword wide
		$s2 = "(&(objectClass=user)(objectCategory=person)" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <200KB and all of them )
}
