rule SIGNATURE_BASE_Equationgroup_Ebbisland : FILE
{
	meta:
		description = "Equation Group hack tool leaked by ShadowBrokers- file ebbisland"
		author = "Florian Roth (Nextron Systems)"
		id = "d30b9f26-c2c5-5ecb-9f63-e96017788e40"
		date = "2017-04-08"
		modified = "2023-12-05"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp_apr17.yar#L576-L594"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "1f4b5054d4239e23146f0764ffe9037b658ecdb9a5f479956c5c45abc1012a17"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "eba07c98c7e960bb6c71dafde85f5da9f74fd61bc87793c87e04b1ae2d77e977"

	strings:
		$x1 = "Usage: %s [-V] -t <target_ip> -p port" fullword ascii
		$x2 = "error - shellcode not as expected - unable to fix up" fullword ascii
		$x3 = "WARNING - core wipe mode - this will leave a core file on target" fullword ascii
		$x4 = "[-C] wipe target core file (leaves less incriminating core on failed target)" fullword ascii
		$x5 = "-A <jumpAddr> (shellcode address)" fullword ascii
		$x6 = "*** Insane undocumented incremental port mode!!! ***" fullword ascii

	condition:
		filesize <250KB and 1 of them
}
