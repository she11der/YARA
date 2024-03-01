rule SIGNATURE_BASE_Equationgroup_Noclient_3_3_2 : FILE
{
	meta:
		description = "Equation Group hack tool set"
		author = "Florian Roth (Nextron Systems)"
		id = "be7c4263-e8e3-5a83-9003-063225e544ff"
		date = "2017-04-09"
		modified = "2023-12-05"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp_apr17.yar#L1119-L1136"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "14b1f135da81fd9a071e0f692bc7f1ab6f6f63d7dd05e1557e5c2d51135727b6"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "3cf0eb010c431372af5f32e2ee8c757831215f8836cabc7d805572bb5574fc72"

	strings:
		$x1 = "127.0.0.1 is not advisable as a source. Use -l 127.0.0.1 to override this warning" fullword ascii
		$x2 = "iptables -%c OUTPUT -p tcp -d 127.0.0.1 --tcp-flags RST RST -j DROP;" fullword ascii
		$x3 = "noclient: failed to execute %s: %s" fullword ascii
		$x4 = "sh -c \"ping -c 2 %s; grep %s /proc/net/arp >/tmp/gx \"" fullword ascii
		$s5 = "Attempting connection from 0.0.0.0:" ascii

	condition:
		( filesize <1000KB and 1 of them )
}
