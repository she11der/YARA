import "pe"

rule SIGNATURE_BASE_EQGRP_Teflonhandle : FILE
{
	meta:
		description = "Detects tool from EQGRP toolset - file teflonhandle.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "4d82cc41-3777-5f8c-9392-aca69e6ed781"
		date = "2016-08-15"
		modified = "2023-12-05"
		reference = "Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp.yar#L94-L111"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "7dfa713b763c983219f008405e1ebf3dfe386672f2d4e5fb54b2b362023ae08a"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "%s [infile] [outfile] /k 0x[%i character hex key] </g>" fullword ascii
		$s2 = "File %s already exists.  Overwrite? (y/n) " fullword ascii
		$s3 = "Random Key : 0x" fullword ascii
		$s4 = "done (%i bytes written)." fullword ascii
		$s5 = "%s --> %s..." fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <20KB and 2 of them
}
