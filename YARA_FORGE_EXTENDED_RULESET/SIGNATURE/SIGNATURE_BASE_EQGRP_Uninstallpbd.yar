import "pe"

rule SIGNATURE_BASE_EQGRP_Uninstallpbd
{
	meta:
		description = "EQGRP Toolset Firewall - file uninstallPBD.bat"
		author = "Florian Roth (Nextron Systems)"
		id = "0153cb2a-a0de-51f9-80c2-22136d56f16d"
		date = "2016-08-16"
		modified = "2023-12-05"
		reference = "Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_eqgrp.yar#L744-L759"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "51be8a491a1e228dfc6156a86e9f2ffc923c39d0649bbc031ea1bafe1af22a45"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "692fdb449f10057a114cf2963000f52ce118d9a40682194838006c66af159bd0"

	strings:
		$s1 = "memset 00e9a05c 4 38845b88" fullword ascii
		$s2 = "_hidecmd" ascii
		$s3 = "memset 013abd04 1 0d" fullword ascii

	condition:
		all of them
}
