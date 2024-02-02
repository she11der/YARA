rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17_Mstcp32_DXGHLP16_Tdip___FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "5b54e68b-7bf3-59a0-8257-c370a3b9e4db"
		date = "2017-04-15"
		modified = "2023-01-06"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_eqgrp_apr17.yar#L2918-L2938"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "35fab86ca4cb287c8046a1764a91523673e12b5729d87c90b0c298dcbfcf86eb"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "26215bc56dc31d2466d72f1f4e1b6388e62606e9949bc41c28968fcb9a9d60a6"
		hash2 = "fcfb56fa79d2383d34c471ef439314edc2239d632a880aa2de3cea430f6b5665"
		hash3 = "a5ec4d102d802ada7c5083af53fd9d3c9b5aa83be9de58dbb4fac7876faf6d29"

	strings:
		$s1 = "\\Registry\\User\\CurrentUser\\" wide
		$s2 = "\\DosDevices\\%ws" wide
		$s3 = "\\Device\\%ws_%ws" wide
		$s4 = "sys\\mstcp32.dbg" fullword ascii
		$s5 = "%ws%03d%ws%wZ" fullword wide
		$s6 = "TCP/IP driver" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <200KB and 4 of them )
}