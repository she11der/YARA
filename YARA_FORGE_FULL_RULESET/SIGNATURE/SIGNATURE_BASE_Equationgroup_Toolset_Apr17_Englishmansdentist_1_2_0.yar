rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17_Englishmansdentist_1_2_0 : FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "76367c53-9b48-59a1-9ac9-8649fd833fe3"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp_apr17.yar#L1834-L1848"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "cd415731c1c8398d2b0b1758c4e7eb3e708620b269f9312cf0a750ab2099162e"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "2a6ab28885ad7d5d64ac4c4fb8c619eca3b7fb3be883fc67c90f3ea9251f34c6"

	strings:
		$x1 = "[+] CheckCredentials(): Checking to see if valid username/password" fullword ascii
		$x2 = "Error connecting to target, TbMakeSocket() %s:%d." fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <200KB and 1 of them )
}
