rule SIGNATURE_BASE_Equationgroup_Cursezinger_Linuxrh7_3_V_2_0_0 : FILE
{
	meta:
		description = "Equation Group hack tool set"
		author = "Florian Roth (Nextron Systems)"
		id = "d4cab478-da1e-54ef-995a-897d1813619e"
		date = "2017-04-09"
		modified = "2023-12-05"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_eqgrp_apr17.yar#L1205-L1221"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "fa56fe4dd44d266741a3f0b0edfc24660b260c1ade45c23171f22bc43a3bee75"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "af7c7d03f59460fa60c48764201e18f3bd3f72441fd2e2ff6a562291134d2135"

	strings:
		$s1 = ",%02d%03d" fullword ascii
		$s2 = "[%.2u%.2u%.2u%.2u%.2u%.2u]" fullword ascii
		$s3 = "__strtoll_internal" ascii
		$s4 = "__strtoul_internal" ascii

	condition:
		( uint16(0)==0x457f and filesize <400KB and all of them )
}
