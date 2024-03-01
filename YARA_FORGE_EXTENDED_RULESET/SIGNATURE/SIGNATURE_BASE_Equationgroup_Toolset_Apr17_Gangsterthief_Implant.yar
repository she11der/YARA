rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17_Gangsterthief_Implant : FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "9127f280-135e-5f83-9587-eab3ad84ad69"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_eqgrp_apr17.yar#L2976-L2993"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "c8145d6eedf20cf95baf329a6240b5b740273ff0a7f82edd3c346eb8c67e69e1"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "50b269bda5fedcf5a62ee0514c4b14d48d53dd18ac3075dcc80b52d0c2783e06"

	strings:
		$s1 = "\\\\.\\%s:" fullword wide
		$s4 = "raw_open CreateFile error" fullword ascii
		$s5 = "-PATHDELETED-" ascii
		$s6 = "(deleted)" fullword wide
		$s8 = "NULLFILENAME" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <300KB and 3 of them )
}
