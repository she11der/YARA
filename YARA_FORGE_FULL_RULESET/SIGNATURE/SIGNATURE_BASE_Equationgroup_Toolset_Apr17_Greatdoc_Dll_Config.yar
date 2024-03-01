rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17_Greatdoc_Dll_Config : FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "592e4e40-f5cd-5a11-8a1b-0cdcf6f267ec"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp_apr17.yar#L2131-L2147"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "edb14cc9e51bbf6b3ca2c52f841edfa3df1ca89b3e7c1b5a59baf3a13be0fc46"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "fd9d0abfa727784dd07562656967d220286fc0d63bcf7e2c35d4c02bc2e5fc2e"

	strings:
		$x1 = "C:\\Projects\\GREATERDOCTOR\\trunk\\GREATERDOCTOR" ascii
		$x2 = "src\\build\\Release\\dllConfig\\dllConfig.pdb" ascii
		$x3 = "GREATERDOCTOR [ commandline args configuration ]" fullword ascii
		$x4 = "-useage: <scanner> \"<cmdline args>\"" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <200KB and 1 of them )
}
