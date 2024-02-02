rule SIGNATURE_BASE_Equationgroup_Ebbshave___FILE
{
	meta:
		description = "Equation Group hack tool leaked by ShadowBrokers- file ebbshave.v5"
		author = "Florian Roth (Nextron Systems)"
		id = "6d4c14e2-afb1-57ce-91df-cb024258250e"
		date = "2017-04-08"
		modified = "2023-12-05"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_eqgrp_apr17.yar#L399-L415"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "8a1a5ddefc646dc55161eb9b2a1b0e4176df7e99660db48b245af3ef9ab0871c"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "eb5e0053299e087c87c2d5c6f90531cc1946019c85a43a2998c7b66a6f19ca4b"

	strings:
		$s1 = "executing ./ebbnew_linux -r %s -v %s -A %s %s -t %s -p %s" fullword ascii
		$s2 = "./ebbnew_linux.wrapper -o 2 -v 2 -t 192.168.10.4 -p 32772" fullword ascii
		$s3 = "version 1 - Start with option #18 first, if it fails then try this option" fullword ascii
		$s4 = "%s is a wrapper program for ebbnew_linux exploit for Sparc Solaris RPC services" fullword ascii

	condition:
		( uint16(0)==0x457f and filesize <20KB and 1 of them ) or (2 of them )
}