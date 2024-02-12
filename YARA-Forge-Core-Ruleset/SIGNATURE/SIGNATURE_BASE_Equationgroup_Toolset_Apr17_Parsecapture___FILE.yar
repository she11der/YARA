rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17_Parsecapture___FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "11743260-c5ce-59de-9fcf-0c050eee98ff"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_eqgrp_apr17.yar#L3096-L3111"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "8946bc6d1812a998757a4032755f37aa2be6121a958ebfb6fec90fa60da038fb"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "c732d790088a4db148d3291a92de5a449e409704b12e00c7508d75ccd90a03f2"

	strings:
		$x1 = "* Encrypted log found.  An encryption key must be provided" fullword ascii
		$x2 = "encryptionkey = e.g., \"00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff\"" fullword ascii
		$x3 = "Decrypting with key '%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x'" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <50KB and 1 of them )
}