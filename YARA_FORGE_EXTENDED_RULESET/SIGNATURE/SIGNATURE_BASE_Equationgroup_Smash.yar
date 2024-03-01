rule SIGNATURE_BASE_Equationgroup_Smash : FILE
{
	meta:
		description = "Equation Group hack tool leaked by ShadowBrokers- file smash"
		author = "Florian Roth (Nextron Systems)"
		id = "9a8cb090-4f47-5674-accb-f233dbb19b71"
		date = "2017-04-08"
		modified = "2023-12-05"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_eqgrp_apr17.yar#L717-L732"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "073496e34dded05be40ee851442f9c0ec998f35e02a5d4221677a195b792f786"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "1dc94b46aaff06d65a3bf724c8701e5f095c1c9c131b65b2f667e11b1f0129a6"

	strings:
		$x1 = "T=<target IP> [O=<port>] Y=<target type>" fullword ascii
		$x2 = "no command given!! bailing..." fullword ascii
		$x3 = "no port. assuming 22..." fullword ascii

	condition:
		filesize <250KB and 1 of them
}
