rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17__Nameprobe_SMBTOUCH_14 : FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "b3b7037b-d08e-5b32-93ec-870f8ce088ac"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_eqgrp_apr17.yar#L3518-L3535"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "c60fc34aa42810a5622fbe53122ded4ffb4ee321fed1badd481ce5c2ae5225ef"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash1 = "fbe3a4501654438f502a93f51b298ff3abf4e4cad34ce4ec0fad5cb5c2071597"
		hash2 = "7da350c964ea43c149a12ac3d2ce4675cedc079ddc10d1f7c464b16688305309"

	strings:
		$s1 = "DEC Pathworks TCPIP service on Windows NT" fullword ascii
		$s2 = "<\\\\__MSBROWSE__> G" fullword ascii
		$s3 = "<IRISNAMESERVER>" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <300KB and all of them )
}
