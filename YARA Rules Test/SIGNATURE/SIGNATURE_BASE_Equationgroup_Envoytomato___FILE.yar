rule SIGNATURE_BASE_Equationgroup_Envoytomato___FILE
{
	meta:
		description = "Equation Group hack tool leaked by ShadowBrokers- file envoytomato"
		author = "Florian Roth (Nextron Systems)"
		id = "d1a43c98-9448-5a03-824d-5cd8e959fbf5"
		date = "2017-04-08"
		modified = "2023-12-05"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_eqgrp_apr17.yar#L701-L715"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "f15b3b4281ec45a7a71c9bf8b88c60befec665f78b76a615c5912a6b7f94235b"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "9bd001057cc97b81fdf2450be7bf3b34f1941379e588a7173ab7fffca41d4ad5"

	strings:
		$s1 = "[-] kernel not vulnerable" fullword ascii
		$s2 = "[-] failed to spawn shell" fullword ascii

	condition:
		filesize <250KB and 1 of them
}