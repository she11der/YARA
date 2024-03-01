rule SIGNATURE_BASE_Equationgroup_Cmsd : FILE
{
	meta:
		description = "Equation Group hack tool leaked by ShadowBrokers- file cmsd"
		author = "Florian Roth (Nextron Systems)"
		id = "9cdd3562-fed4-5b79-b056-049279404eeb"
		date = "2017-04-08"
		modified = "2023-12-05"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_eqgrp_apr17.yar#L380-L397"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "2b9c7ef750c2e45df7839395db51c93204bc9855f5de05bd59c50bb6a964bc8b"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "634c50614e1f5f132f49ae204c4a28f62a32a39a3446084db5b0b49b564034b8"

	strings:
		$x1 = "usage: %s address [-t][-s|-c command] [-p port] [-v 5|6|7]" fullword ascii
		$x2 = "error: not vulnerable" fullword ascii
		$s1 = "port=%d connected! " fullword ascii
		$s2 = "xxx.XXXXXX" fullword ascii

	condition:
		( uint16(0)==0x457f and filesize <30KB and 1 of ($x*)) or (2 of them )
}
