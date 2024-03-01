rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17_Lp_Mstcp : FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "afa4985e-7c8f-58fc-9881-219ccba6a495"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_eqgrp_apr17.yar#L2526-L2545"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "5d1423661f95d955f411414138da45cc4be59b2e6bf8e70f471b8f41fc9ea3f4"
		score = 75
		quality = 83
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "2ab1e1d23021d887759750a0c053522e9149b7445f840936bbc7e703f8700abd"

	strings:
		$s1 = "\\Registry\\User\\CurrentUser\\" wide
		$s2 = "_PacketNDISRequestComplete@12\"" fullword ascii
		$s3 = "_LDNdis5RegDeleteKeys@4" ascii
		$op1 = { 89 7e 04 75 06 66 21 46 02 eb }
		$op2 = { fc 74 1b 8b 49 04 0f b7 d3 66 83 }
		$op3 = { aa 0f b7 45 fc 8b 52 04 8d 4e }

	condition:
		( uint16(0)==0x5a4d and filesize <100KB and ( all of ($s*) or all of ($op*)))
}
