rule SIGNATURE_BASE_Equationgroup__Pclean_V2_1_1_Pclean_V2_1_1_4 : FILE
{
	meta:
		description = "Equation Group hack tool leaked by ShadowBrokers- from files pclean.v2.1.1.0-linux-i386, pclean.v2.1.1.0-linux-x86_64"
		author = "Florian Roth (Nextron Systems)"
		id = "ed4a3b3a-0935-533b-80dd-ee23b2e8df00"
		date = "2017-04-08"
		modified = "2023-12-05"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_eqgrp_apr17.yar#L914-L930"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "5622d6fff876fa5d07795491d14f0396378c1b07b69cf8bcabb5e0bd3c19e72a"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash1 = "cdb5b1173e6eb32b5ea494c38764b9975ddfe83aa09ba0634c4bafa41d844c97"
		hash2 = "ab7f26faed8bc2341d0517d9cb2bbf41795f753cd21340887fc2803dc1b9a1dd"

	strings:
		$s1 = "-c cmd_name:     strncmp() search for 1st %d chars of commands that " fullword ascii
		$s2 = "e.g.: -n 1-1024,1080,6666,31337 " fullword ascii

	condition:
		( uint16(0)==0x457f and filesize <50KB and all of them )
}
