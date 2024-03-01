rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17_Remotecommand_Lp : FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "98ace4d7-edd0-5e84-bac8-b69e5307f567"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp_apr17.yar#L2510-L2524"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "974772264324e7721f51a88534aaa3b4eb1d409e04f673783caf4849d90522de"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "57b47613a3b5dd820dae59fc6dc2b76656bd578f015f367675219eb842098846"

	strings:
		$s1 = "Failure parsing command from %hs:%u: os=%u plugin=%u" fullword wide
		$s2 = "Unable to get TCP listen port: %08x" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <200KB and all of them )
}
