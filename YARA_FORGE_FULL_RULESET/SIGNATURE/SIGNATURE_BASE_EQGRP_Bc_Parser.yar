import "pe"

rule SIGNATURE_BASE_EQGRP_Bc_Parser : FILE
{
	meta:
		description = "Detects tool from EQGRP toolset - file bc-parser"
		author = "Florian Roth (Nextron Systems)"
		id = "ed4523de-b126-503a-83bd-aafd8533b0e5"
		date = "2016-08-15"
		modified = "2023-12-05"
		reference = "Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp.yar#L172-L187"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "e8911acc1173e1149fd11dd795b72ba26bc654cbc7f9d95053ce420663fcafe9"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "879f2f1ae5d18a3a5310aeeafec22484607649644e5ecb7d8a72f0877ac19cee"

	strings:
		$s1 = "*** Target may be susceptible to FALSEMOREL      ***" fullword ascii
		$s2 = "*** Target is susceptible to FALSEMOREL          ***" fullword ascii

	condition:
		uint16(0)==0x457f and 1 of them
}
