rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17_Aduser_Implant : FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "4ba152c8-aa81-5558-8ad3-c62aa3231dab"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_eqgrp_apr17.yar#L2072-L2086"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "d378773f4acd850e5a8d92d6cce84d57f659330edc025565cf4bc34afb0a6ae6"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "fd2efb226969bc82e2e38769a10a8a751138db69f4594a8de4b3c0522d4d885f"

	strings:
		$s1 = ".?AVFeFinallyFailure@@" fullword ascii
		$s2 = "(&(objectCategory=person)(objectClass=user)(cn=" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <40KB and all of them )
}
