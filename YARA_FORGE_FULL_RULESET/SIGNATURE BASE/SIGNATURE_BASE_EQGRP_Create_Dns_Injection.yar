import "pe"

rule SIGNATURE_BASE_EQGRP_Create_Dns_Injection
{
	meta:
		description = "EQGRP Toolset Firewall - file create_dns_injection.py"
		author = "Florian Roth (Nextron Systems)"
		id = "ef358ca6-ebd8-5d08-944b-f1fcd112f1f3"
		date = "2016-08-16"
		modified = "2023-12-05"
		reference = "Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp.yar#L252-L266"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "a07cb33c459208410b326fc260e96e617385ee4eac905a92d9542cb5ec73713e"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "488f3cc21db0688d09e13eb85a197a1d37902612c3e302132c84e07bc42b1c32"

	strings:
		$s1 = "Name:   A hostname: 'host.network.com', a decimal numeric offset within" fullword ascii
		$s2 = " www.badguy.net,CNAME,1800,host.badguy.net \\\\" ascii

	condition:
		1 of them
}
