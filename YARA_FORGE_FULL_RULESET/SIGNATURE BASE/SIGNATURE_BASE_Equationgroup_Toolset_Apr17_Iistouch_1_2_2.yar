rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17_Iistouch_1_2_2 : FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "dd6ea8cc-505d-5c7c-a7ea-c5fa4f14b5ee"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp_apr17.yar#L1765-L1779"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "f4f5e17d3777d6ae8bfd0646eeffcd631331e4d8966f5124ebc9352438dc790f"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "c433507d393a8aa270576790acb3e995e22f4ded886eb9377116012e247a07c6"

	strings:
		$x1 = "[-] Are you being redirectect? Need to retarget?" fullword ascii
		$x2 = "[+] IIS Target OS: %s" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <60KB and 1 of them )
}
