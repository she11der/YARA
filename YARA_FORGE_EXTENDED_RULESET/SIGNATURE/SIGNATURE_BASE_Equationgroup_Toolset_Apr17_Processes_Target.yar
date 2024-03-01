rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17_Processes_Target : FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "1b910f46-5d19-5ecd-9647-10ee9ee7b012"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_eqgrp_apr17.yar#L2221-L2236"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "e9e26224b7eafc999c9638d4591a45297e3293b0e90e63c2d207ee52848c4ce2"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "69cf7643dbecc5f9b4b29edfda6c0295bc782f0e438f19be8338426f30b4cc74"

	strings:
		$s1 = "Select * from Win32_Process" fullword ascii
		$s3 = "\\\\%ls\\root\\cimv2" fullword wide
		$s5 = "%4ls%2ls%2ls%2ls%2ls%2ls.%11l[0-9]%1l[+-]%6s" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <200KB and 2 of them )
}
