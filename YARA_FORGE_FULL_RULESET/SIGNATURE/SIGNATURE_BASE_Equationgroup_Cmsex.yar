rule SIGNATURE_BASE_Equationgroup_Cmsex : FILE
{
	meta:
		description = "Equation Group hack tool leaked by ShadowBrokers- file cmsex"
		author = "Florian Roth (Nextron Systems)"
		id = "9a1051a5-3f31-5fc2-85a0-beb2dea962d6"
		date = "2017-04-08"
		modified = "2023-12-05"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp_apr17.yar#L503-L520"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "997e08a49c5ae82bcc590e5febd449a4d3e9098f5aa154ccc0824b976f0a6365"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "2d8ae842e7b16172599f061b5b1f223386684a7482e87feeb47a38a3f011b810"

	strings:
		$x1 = "Usage: %s -i <ip_addr/hostname> -c <command> -T <target_type> (-u <port> | -t <port>) " fullword ascii
		$x2 = "-i target ip address / hostname " fullword ascii
		$x3 = "Note: Choosing the correct target type is a bit of guesswork." fullword ascii
		$x4 = "Solaris rpc.cmsd remote root exploit" fullword ascii
		$x5 = "If one choice fails, you may want to try another." fullword ascii

	condition:
		( uint16(0)==0x457f and filesize <50KB and 1 of ($x*)) or (2 of them )
}
