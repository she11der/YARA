rule SIGNATURE_BASE_Equationgroup_Epoxyresin_V1_0_0___FILE
{
	meta:
		description = "Equation Group hack tool leaked by ShadowBrokers- file epoxyresin.v1.0.0.1"
		author = "Florian Roth (Nextron Systems)"
		id = "390a13b0-3246-5bf7-8841-775a43045172"
		date = "2017-04-08"
		modified = "2023-12-05"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_eqgrp_apr17.yar#L664-L681"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "c1cbc18f05b299837463aa27a9c47ea0355ca5974b2c6ab1e0a18cc9ad1b26a1"
		score = 75
		quality = 83
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "eea8a6a674d5063d7d6fc9fe07060f35b16172de6d273748d70576b01bf01c73"

	strings:
		$x1 = "[-] kernel not vulnerable" fullword ascii
		$s1 = ".tmp.%d.XXXXXX" fullword ascii
		$s2 = "[-] couldn't create temp file" fullword ascii
		$s3 = "/boot/System.map-%s" fullword ascii

	condition:
		( uint16(0)==0x457f and filesize <30KB and $x1) or ( all of them )
}