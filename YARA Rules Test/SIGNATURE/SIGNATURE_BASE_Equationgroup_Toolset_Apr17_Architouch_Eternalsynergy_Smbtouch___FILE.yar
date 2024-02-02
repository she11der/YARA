rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17_Architouch_Eternalsynergy_Smbtouch___FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "df3b0794-cbbd-530c-8425-fdf4b116b870"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_eqgrp_apr17.yar#L1850-L1870"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "faeac75104a15cac8528663a82eadbc7bc22cc0a1d1a3b3dfccb6ea46fb24a67"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash1 = "444979a2387530c8fbbc5ddb075b15d6a4717c3435859955f37ebc0f40a4addc"
		hash2 = "92c6a9e648bfd98bbceea3813ce96c6861487826d6b2c3d462debae73ed25b34"
		hash3 = "108243f61c53f00f8f1adcf67c387a8833f1a2149f063dd9ef29205c90a3c30a"

	strings:
		$s1 = "NtErrorMoreProcessingRequired" fullword ascii
		$s2 = "Command Format Error: Error=%x" fullword ascii
		$s3 = "NtErrorPasswordRestriction" fullword ascii
		$op0 = { 8a 85 58 ff ff ff 88 43 4d }

	condition:
		( uint16(0)==0x5a4d and filesize <600KB and 2 of them )
}