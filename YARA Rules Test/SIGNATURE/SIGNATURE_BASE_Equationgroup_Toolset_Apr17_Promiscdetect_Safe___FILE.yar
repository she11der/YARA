rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17_Promiscdetect_Safe___FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "d6103861-b332-5c21-8408-76b512012689"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_eqgrp_apr17.yar#L2620-L2635"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "4b8c2e9a00af4e6aed7f603dee0439357e3389180fbd2e83d6809e76dc7d0428"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "6070d8199061870387bb7796fb8ccccc4d6bafed6718cbc3a02a60c6dc1af847"

	strings:
		$s1 = "running on this computer!" fullword ascii
		$s2 = "- Promiscuous (capture all packets on the network)" fullword ascii
		$s3 = "Active filter for the adapter:" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <80KB and all of them )
}