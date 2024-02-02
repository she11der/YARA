rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17_EXPA___FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "106efe9b-f70f-51cf-bbb2-b9bf61df1dd1"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_eqgrp_apr17.yar#L2311-L2327"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "2aa4ee5b128714cfa7f5d29f7ef110e1b18fb7bc21351444b2472ff74c4139d3"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "2017176d3b5731a188eca1b71c50fb938c19d6260c9ff58c7c9534e317d315f8"

	strings:
		$x1 = "* The target is IIS 6.0 but is not running content indexing servicess," fullword ascii
		$x2 = "--ver 6 --sp <service_pack> --lang <language> --attack shellcode_option[s]sL" fullword ascii
		$x3 = "By default, the shellcode will attempt to immediately connect s$" fullword ascii
		$x4 = "UNEXPECTED SHELLCODE CONFIGURATION ERRORs" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <12000KB and 1 of them )
}