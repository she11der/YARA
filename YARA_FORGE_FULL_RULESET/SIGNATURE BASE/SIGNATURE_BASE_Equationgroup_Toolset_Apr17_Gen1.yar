rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17_Gen1 : FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "98b0a398-7761-5506-bd2f-117c118df11f"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp_apr17.yar#L1965-L1984"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "cd40d51ba26706517dae332d84f574eb206a424693cfb586375695e364990b5d"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash1 = "1b5b33931eb29733a42d18d8ee85b5cd7d53e81892ff3e60e2e97f3d0b184d31"
		hash2 = "139697168e4f0a2cc73105205c0ddc90c357df38d93dbade761392184df680c7"

	strings:
		$x1 = "Restart with the new protocol, address, and port as target." fullword ascii
		$x2 = "TargetPort      : %s (%u)" fullword ascii
		$x3 = "Error: strchr() could not find '@' in account name." fullword ascii
		$x4 = "TargetAcctPwd   : %s" fullword ascii
		$x5 = "Creating CURL connection handle..." fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <80KB and 1 of them )
}
