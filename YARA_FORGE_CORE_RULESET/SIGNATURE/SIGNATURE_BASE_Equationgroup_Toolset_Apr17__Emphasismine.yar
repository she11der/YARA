rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17__Emphasismine : FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "cc684f39-4971-52e0-b5ec-d28c7ce7032b"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_eqgrp_apr17.yar#L1891-L1910"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "20ec32f5e9e439fb212985d5ae104ae5742231f594423cd125a9e64ed6eb234a"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash1 = "dcaf91bd4af7cc7d1fb24b5292be4e99c7adf4147892f6b3b909d1d84dd4e45b"
		hash2 = "348eb0a6592fcf9da816f4f7fc134bcae1b61c880d7574f4e19398c4ea467f26"

	strings:
		$x1 = "Error: Could not calloc() for shellcode buffer" fullword ascii
		$x2 = "shellcodeSize: 0x%04X + 0x%04X + 0x%04X = 0x%04X" fullword ascii
		$x3 = "Generating shellcode" fullword ascii
		$x4 = "([0-9a-zA-Z]+) OK LOGOUT completed" fullword ascii
		$x5 = "Error: Domino is not the expected version. (%s, %s)" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <100KB and 1 of them )
}
