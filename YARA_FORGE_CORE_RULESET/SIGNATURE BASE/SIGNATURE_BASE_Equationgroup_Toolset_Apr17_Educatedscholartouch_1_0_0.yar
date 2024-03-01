rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17_Educatedscholartouch_1_0_0 : FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "62205374-25a3-5b96-ad0a-a82c9a01a242"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_eqgrp_apr17.yar#L1668-L1682"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "4c06fad158db8337ff768ad1553401ec31eee6b0d50333ce91a3a12e79d8981a"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "f4b958a0d3bb52cb34f18ea293d43fa301ceadb4a259d3503db912d0a9a1e4d8"

	strings:
		$x1 = "[!] A vulnerable target will not respond." fullword ascii
		$x2 = "[-] Target NOT Vulernable" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <30KB and 1 of them )
}
