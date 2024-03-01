import "pe"

rule SIGNATURE_BASE_EQGRP_BFLEA_2201 : FILE
{
	meta:
		description = "EQGRP Toolset Firewall - file BFLEA-2201.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "7dfdc2a2-73d1-5eba-8936-ed14b17495c5"
		date = "2016-08-16"
		modified = "2023-12-05"
		reference = "Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_eqgrp.yar#L804-L823"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "d0fd4d0ffe98856abed685c4b9ff770daba22aa16bd860440874fd94df2d54ea"
		score = 75
		quality = 83
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "15e8c743770e44314496c5f27b6297c5d7a4af09404c4aa507757e0cc8edc79e"

	strings:
		$s1 = ".got_loader" fullword ascii
		$s2 = "LOADED" fullword ascii
		$s3 = "readFlashHandler" fullword ascii
		$s4 = "KEEPGOING" fullword ascii
		$s5 = "flashRtnsPix6x.c" fullword ascii
		$s6 = "fix_ip_cksum_incr" fullword ascii
		$s7 = "writeFlashHandler" fullword ascii

	condition:
		( uint16(0)==0x457f and filesize <30KB and 5 of them ) or ( all of them )
}
