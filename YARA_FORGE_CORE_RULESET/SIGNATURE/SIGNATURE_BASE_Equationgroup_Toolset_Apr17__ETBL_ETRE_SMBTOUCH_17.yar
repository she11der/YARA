rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17__ETBL_ETRE_SMBTOUCH_17 : FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "88bf610d-1c6e-554a-af82-46b5eb3cc6a5"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_eqgrp_apr17.yar#L3580-L3597"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "ef86350732b5064035ff58b63202be29e906d2b566af105f03298e3e339eda52"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash1 = "70db3ac2c1a10de6ce6b3e7a7890c37bffde006ea6d441f5de6d8329add4d2ef"
		hash2 = "e0f05f26293e3231e4e32916ad8a6ee944af842410c194fce8a0d8ad2f5c54b2"
		hash3 = "7da350c964ea43c149a12ac3d2ce4675cedc079ddc10d1f7c464b16688305309"

	strings:
		$x1 = "ERROR: Connection terminated by Target (TCP Ack/Fin)" fullword ascii
		$s2 = "Target did not respond within specified amount of time" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <300KB and 1 of them )
}
