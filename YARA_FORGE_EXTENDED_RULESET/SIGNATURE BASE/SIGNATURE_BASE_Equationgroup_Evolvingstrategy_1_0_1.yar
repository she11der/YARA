rule SIGNATURE_BASE_Equationgroup_Evolvingstrategy_1_0_1 : FILE
{
	meta:
		description = "Equation Group hack tool leaked by ShadowBrokers- file evolvingstrategy.1.0.1.1"
		author = "Florian Roth (Nextron Systems)"
		id = "465f709b-1791-5b36-836b-7a0c08bb9b88"
		date = "2017-04-08"
		modified = "2023-12-05"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_eqgrp_apr17.yar#L170-L188"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "87d25f1a4ca4a75292ab6cdcd1a79890c4475c2a9b34761ed92988bd517b4497"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "fe70e16715992cc86bbef3e71240f55c7d73815b4247d7e866c845b970233c1b"

	strings:
		$s1 = "chown root sh; chmod 4777 sh;" fullword ascii
		$s2 = "cp /bin/sh .;chown root sh;" fullword ascii
		$l1 = "echo clean up when elevated:" fullword ascii
		$x1 = "EXE=$DIR/sbin/ey_vrupdate" fullword ascii

	condition:
		( filesize <4KB and 1 of them )
}
