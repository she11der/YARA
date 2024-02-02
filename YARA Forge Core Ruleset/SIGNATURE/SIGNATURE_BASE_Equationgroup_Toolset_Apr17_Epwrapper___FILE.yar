rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17_Epwrapper___FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "81b72f7f-ba5a-5f45-b77c-071cfb4571d3"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_eqgrp_apr17.yar#L2256-L2271"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "9a1a54cd3fef3db9a20f3be25336fcbabe0d993403f001a04a02b5dbfd629543"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "a8eed17665ee22198670e22458eb8c9028ff77130788f24f44986cce6cebff8d"

	strings:
		$x1 = "* Failed to get remote TCP socket address" fullword wide
		$x2 = "* Failed to get 'LPStart' export" fullword wide
		$s5 = "Usage: %ls <logdir> <dll_search_path> <dll_to_load_path> <socket>" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <20KB and 1 of them )
}