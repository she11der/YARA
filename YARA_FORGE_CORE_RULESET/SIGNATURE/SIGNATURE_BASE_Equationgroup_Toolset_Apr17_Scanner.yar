rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17_Scanner : FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "603c82d0-2e65-5353-a109-5f69697cffa4"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_eqgrp_apr17.yar#L2149-L2166"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "7f2ee4ac260b78764573187c501ed27fbfdf573e618f15dbd307177afa670605"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "f180bdb247687ea9f1b58aded225d5c80a13327422cd1e0515ea891166372c53"

	strings:
		$x1 = "+daemon_version,system,processor,refid,clock" fullword ascii
		$x2 = "Usage: %s typeofscan IP_address" fullword ascii
		$x3 = "# scanning ip  %d.%d.%d.%d" fullword ascii
		$x4 = "Welcome to the network scanning tool" fullword ascii
		$x5 = "***** %s ***** (length %d)" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <90KB and 1 of them )
}
