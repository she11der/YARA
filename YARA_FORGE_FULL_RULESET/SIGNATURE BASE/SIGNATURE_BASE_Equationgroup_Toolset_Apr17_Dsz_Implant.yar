rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17_Dsz_Implant : FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "febc8654-7dc3-5c8b-a53c-f8d7dc29b14b"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp_apr17.yar#L2741-L2755"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "3d76131a42aed642a8c54076544488a8d24ec16416469813324541d72e30101b"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "fbe103fac45abe4e3638055a3cac5e7009166f626cf2d3049fb46f3b53c1057f"
		hash2 = "ad1dddd11b664b7c3ad6108178a8dade0a6d9795358c4a7cedbe789c62016670"

	strings:
		$s1 = "%02u:%02u:%02u.%03u-%4u: " fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <1000KB and all of them )
}
