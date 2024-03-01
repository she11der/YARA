rule SIGNATURE_BASE_Equationgroup_Xspy : FILE
{
	meta:
		description = "Equation Group hack tool leaked by ShadowBrokers- file xspy"
		author = "Florian Roth (Nextron Systems)"
		id = "fcb7246a-d613-51d7-a4f7-f767fa5f79e1"
		date = "2017-04-08"
		modified = "2023-12-05"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_eqgrp_apr17.yar#L786-L799"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "94ab45d6c94c63c5c9c68ee3d509143af4eb574058c0cd4f26eed8058dbd9213"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "841e065c9c340a1e522b281a39753af8b6a3db5d9e7d8f3d69e02fdbd662f4cf"

	strings:
		$s1 = "USAGE: xspy -display <display> -delay <usecs> -up" fullword ascii

	condition:
		( uint16(0)==0x457f and filesize <60KB and all of them )
}
