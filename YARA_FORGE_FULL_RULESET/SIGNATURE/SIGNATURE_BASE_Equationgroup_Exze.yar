rule SIGNATURE_BASE_Equationgroup_Exze : FILE
{
	meta:
		description = "Equation Group hack tool leaked by ShadowBrokers- file exze"
		author = "Florian Roth (Nextron Systems)"
		id = "d452b952-0c4a-501b-93f5-064d13f2c08e"
		date = "2017-04-08"
		modified = "2023-12-05"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp_apr17.yar#L522-L537"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "b8678f58da689be9507a345b6b80ece6cdb7a78d73db339bdc15ad0a66b4a2e6"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "1af6dde6d956db26c8072bf5ff26759f1a7fa792dd1c3498ba1af06426664876"

	strings:
		$s1 = "shellFile" fullword ascii
		$s2 = "completed.1" fullword ascii
		$s3 = "zeke_remove" fullword ascii

	condition:
		( uint16(0)==0x457f and filesize <80KB and all of them )
}
