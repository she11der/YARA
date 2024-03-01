rule SIGNATURE_BASE_Equationgroup_Tnmunger : FILE
{
	meta:
		description = "Equation Group hack tool leaked by ShadowBrokers- file tnmunger"
		author = "Florian Roth (Nextron Systems)"
		id = "c95dd24f-ffc9-5e58-aed7-205daa001b8c"
		date = "2017-04-08"
		modified = "2023-12-05"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_eqgrp_apr17.yar#L120-L134"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "ddb957ca9350288d0fa98ba20847a99dcba931b5a03d0ae94cd3409f82f728eb"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "1ab985d84871c54d36ba4d2abd9168c2a468f1ba06994459db06be13ee3ae0d2"

	strings:
		$s1 = "TEST: mungedport=%6d  pp=%d  unmunged=%6d" fullword ascii
		$s2 = "mungedport=%6d  pp=%d  unmunged=%6d" fullword ascii

	condition:
		( uint16(0)==0x457f and filesize <10KB and 1 of them )
}
