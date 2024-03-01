import "pe"

rule SIGNATURE_BASE_EQGRP_Morel : FILE
{
	meta:
		description = "Detects tool from EQGRP toolset - file morel.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "e741b727-0e41-53d0-832c-df7f4ea7964a"
		date = "2016-08-15"
		modified = "2023-12-05"
		reference = "Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp.yar#L154-L170"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "463d628bb19e27e94dcccc4c7d435d86111d51aa9f77c5ca1a199d9aaa9017ba"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "a9152e67f507c9a179bb8478b58e5c71c444a5a39ae3082e04820a0613cd6d9f"

	strings:
		$s1 = "%d - %d, %d" fullword ascii
		$s2 = "%d - %lu.%lu %d.%lu" fullword ascii
		$s3 = "%d - %d %d" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <60KB and all of them )
}
