import "pe"

rule SIGNATURE_BASE_Equationgroup_Passfreely_Lp : FILE
{
	meta:
		description = "EquationGroup Malware - file PassFreely_Lp.dll"
		author = "Florian Roth (Nextron Systems)"
		id = "5fb99194-f0df-54aa-9f20-7f8458155e62"
		date = "2017-01-13"
		modified = "2023-12-05"
		reference = "https://goo.gl/tcSoiJ"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_eqgrp.yar#L1885-L1900"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "c3ceb04b42b6e741b1578ec9ecb83b72c599d9af457d6d4e8de572e481d3aa5c"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "fe42139748c8e9ba27a812466d9395b3a0818b0cd7b41d6769cb7239e57219fb"

	strings:
		$s1 = "Unexpected value in memory.  Run the 'CheckOracle' or 'memcheck' command to identify the problem" fullword wide
		$s2 = "Oracle process memory successfully modified!" fullword wide
		$s3 = "Unable to reset the memory protection mask to the memory" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <300KB and 1 of them )
}
