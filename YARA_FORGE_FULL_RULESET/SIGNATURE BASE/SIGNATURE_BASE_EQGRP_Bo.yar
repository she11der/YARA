import "pe"

rule SIGNATURE_BASE_EQGRP_Bo : FILE
{
	meta:
		description = "EQGRP Toolset Firewall - file bo"
		author = "Florian Roth (Nextron Systems)"
		id = "6aa71528-3ce6-5597-bb1a-e44cff3856d6"
		date = "2016-08-16"
		modified = "2023-12-05"
		reference = "Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp.yar#L435-L452"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "48c2d3f13283d2a1b7e1010c724f1e68e6002dd9a9779025dfc3a4952bec95bc"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "aa8b363073e8ae754b1836c30f440d7619890ded92fb5b97c73294b15d22441d"

	strings:
		$s1 = "ERROR: failed to open %s: %d" fullword ascii
		$s2 = "__libc_start_main@@GLIBC_2.0" ascii
		$s3 = "serial number: %s" fullword ascii
		$s4 = "strerror@@GLIBC_2.0" fullword ascii
		$s5 = "ERROR: mmap failed: %d" fullword ascii

	condition:
		( uint16(0)==0x457f and filesize <20KB and all of them )
}
