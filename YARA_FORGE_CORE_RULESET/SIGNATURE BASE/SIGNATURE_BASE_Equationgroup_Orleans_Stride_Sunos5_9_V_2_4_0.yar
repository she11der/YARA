rule SIGNATURE_BASE_Equationgroup_Orleans_Stride_Sunos5_9_V_2_4_0 : FILE
{
	meta:
		description = "Equation Group hack tool set"
		author = "Florian Roth (Nextron Systems)"
		id = "ec83e1c0-91a9-5f9d-a1d2-94be725bc05a"
		date = "2017-04-09"
		modified = "2023-12-05"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_eqgrp_apr17.yar#L1171-L1186"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "1380b22e661926ebb2878d89c80e115a58d0bfc060681a55564c97c1e9f36765"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "6a30efb87b28e1a136a66c7708178c27d63a4a76c9c839b2fc43853158cb55ff"

	strings:
		$s1 = "_lib_version" ascii
		$s2 = ",%02d%03d" fullword ascii
		$s3 = "TRANSIT" fullword ascii

	condition:
		( uint16(0)==0x457f and filesize <200KB and all of them )
}
