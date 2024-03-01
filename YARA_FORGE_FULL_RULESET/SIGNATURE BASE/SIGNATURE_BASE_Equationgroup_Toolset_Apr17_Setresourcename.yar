rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17_Setresourcename : FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "dc261147-3b52-57c3-9729-2645a0999a99"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp_apr17.yar#L2397-L2413"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "e26aac30e06da14060a955761d08e6f543db2f2747be2959b0090f60e6eb52a5"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "537793d5158aecd0debae25416450bd885725adfc8ca53b0577a3df4b0222e2e"

	strings:
		$x1 = "Updates the name of the dll or executable in the resource file" fullword ascii
		$x2 = "*NOTE: SetResourceName does not work with PeddleCheap versions" fullword ascii
		$x3 = "2 = [appinit.dll] level4 dll" fullword ascii
		$x4 = "1 = [spcss32.exe] level3 exe" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <100KB and 1 of them )
}
