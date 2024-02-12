rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17_Sldecoder___FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "1760e84b-fc40-5d60-9351-3a3134af9e9f"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_eqgrp_apr17.yar#L3200-L3214"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "81a74169dc8f93f314f384bd859df07a4ffaaf430b221b440de922fad3497535"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "b220f51ca56d9f9d7d899fa240d3328535f48184d136013fd808d8835919f9ce"

	strings:
		$x1 = "Error in conversion. SlDecoder.exe <input filename> <output filename> at command line " fullword wide
		$x2 = "KeyLogger_Data" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <200KB and 1 of them )
}