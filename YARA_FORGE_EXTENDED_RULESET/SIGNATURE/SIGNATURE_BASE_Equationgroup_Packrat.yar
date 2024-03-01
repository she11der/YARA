rule SIGNATURE_BASE_Equationgroup_Packrat : FILE
{
	meta:
		description = "Equation Group hack tool leaked by ShadowBrokers- file packrat"
		author = "Florian Roth (Nextron Systems)"
		id = "4c0619c4-728f-591f-aa02-7c28f1f42fd1"
		date = "2017-04-08"
		modified = "2023-12-05"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_eqgrp_apr17.yar#L241-L256"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "7e88e14e0d9c8e8f5ccca3bea78b875bf75fbf0dd54badc339237ca94f0d6373"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "d3e067879c51947d715fc2cf0d8d91c897fe9f50cae6784739b5c17e8a8559cf"

	strings:
		$x2 = "Use this on target to get your RAT:" fullword ascii
		$x3 = "$ratremotename && " fullword ascii
		$x5 = "$command = \"$nc$bindto -vv -l -p $port < ${ratremotename}\" ;" fullword ascii

	condition:
		( filesize <70KB and 1 of them )
}
