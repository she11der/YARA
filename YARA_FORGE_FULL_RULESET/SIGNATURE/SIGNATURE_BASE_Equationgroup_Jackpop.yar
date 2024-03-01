rule SIGNATURE_BASE_Equationgroup_Jackpop : FILE
{
	meta:
		description = "Equation Group hack tool leaked by ShadowBrokers- file jackpop"
		author = "Florian Roth (Nextron Systems)"
		id = "7c650752-200b-51e7-95c2-4d385bfd5844"
		date = "2017-04-08"
		modified = "2023-12-05"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp_apr17.yar#L596-L614"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "6efc4ccd2727f93713ad35dc1f054fa25e976e8c3d95f00226fbd56d7f1ce30b"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "0b208af860bb2c7ef6b1ae1fcef604c2c3d15fc558ad8ea241160bf4cbac1519"

	strings:
		$x1 = "%x:%d  --> %x:%d %d bytes" fullword ascii
		$s1 = "client: can't bind to local address, are you root?" fullword ascii
		$s2 = "Unable to register port" fullword ascii
		$s3 = "Could not resolve destination" fullword ascii
		$s4 = "raw troubles" fullword ascii

	condition:
		( uint16(0)==0x457f and filesize <30KB and 3 of them ) or ( all of them )
}
