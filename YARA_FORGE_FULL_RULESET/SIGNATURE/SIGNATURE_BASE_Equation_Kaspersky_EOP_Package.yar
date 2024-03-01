rule SIGNATURE_BASE_Equation_Kaspersky_EOP_Package : FILE
{
	meta:
		description = "Equation Group Malware - EoP package and malware launcher"
		author = "Florian Roth (Nextron Systems)"
		id = "2eb97873-a415-57be-a8fb-70ef86a99c9b"
		date = "2015-02-16"
		modified = "2023-12-05"
		reference = "http://goo.gl/ivt8EW"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/spy_equation_fiveeyes.yar#L299-L318"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "2bd1b1f5b4384ce802d5d32d8c8fd3d1dc04b962"
		logic_hash = "abbc562b8e822422ae1852a5675a680e797a6af0be5581a8482785bd0c1ad1bf"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "abababababab" fullword ascii
		$s1 = "abcdefghijklmnopq" fullword ascii
		$s2 = "@STATIC" fullword wide
		$s3 = "$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" fullword ascii
		$s4 = "@prkMtx" fullword wide
		$s5 = "prkMtx" fullword wide
		$s6 = "cnFormVoidFBC" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <100000 and all of ($s*)
}
