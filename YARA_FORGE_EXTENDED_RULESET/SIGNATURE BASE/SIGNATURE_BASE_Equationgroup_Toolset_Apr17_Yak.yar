rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17_Yak : FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "e5562d1a-7980-5fb8-b098-2e26003fb159"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_eqgrp_apr17.yar#L2054-L2070"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "69b9514508f557376d876262793e5650289abfeeeee8b5ca9beaf42f3ec4d64c"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "66ff332f84690642f4e05891a15bf0c9783be2a64edb2ef2d04c9205b47deb19"

	strings:
		$x1 = "-xd = dump archive data & store in scancodes.txt" fullword ascii
		$x2 = "-------- driver start token -------" fullword wide
		$x3 = "-------- keystart token -------" fullword wide
		$x4 = "-xta = same as -xt but show special chars & store in keys_all.txt" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <800KB and 2 of them )
}
