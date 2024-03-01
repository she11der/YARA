rule SIGNATURE_BASE_Equationgroup_Parsescan : FILE
{
	meta:
		description = "Equation Group hack tool leaked by ShadowBrokers- file parsescan"
		author = "Florian Roth (Nextron Systems)"
		id = "bbe8b518-2bf0-5de4-8fb8-9b8609d393dc"
		date = "2017-04-08"
		modified = "2023-12-05"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp_apr17.yar#L616-L630"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "25e0bc21f93cd72814cd6114883ed903af84a62dced126201b6037a476dbd2cd"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "942c12067b0afe9ebce50aa9dfdbf64e6ed0702d9a3a00d25b4fca62a38369ef"

	strings:
		$s1 = "$gotgs=1 if (($line =~ /Scan for (Sol|SNMP)\\s+version/) or" fullword ascii
		$s2 = "Usage:  $prog [-f file] -p prognum [-V ver] [-t proto] -i IPadr" fullword ascii

	condition:
		filesize <250KB and 1 of them
}
