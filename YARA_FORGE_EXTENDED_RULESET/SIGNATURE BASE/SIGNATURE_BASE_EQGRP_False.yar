import "pe"

rule SIGNATURE_BASE_EQGRP_False : FILE
{
	meta:
		description = "Detects tool from EQGRP toolset - file false.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "3a68790b-38fc-570b-8b19-c5478cdd2842"
		date = "2016-08-15"
		modified = "2023-12-05"
		reference = "Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_eqgrp.yar#L113-L134"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "a1938bc7a5a7a1bb382c2bab976013a1adedc045e0312daabe1bdcdd65d0c606"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = { 00 25 64 2E 0A 00 00 00 00 25 64 2E 0A 00 00 00
			00 25 6C 75 2E 25 6C 75 2E 25 6C 75 2E 25 6C 75
			00 25 64 2E 0A 00 00 00 00 25 64 2E 0A 00 00 00
			00 25 64 2E 0A 00 00 00 00 25 64 2E 0A 00 00 00
			00 25 32 2E 32 58 20 00 00 0A 00 00 00 25 64 20
			2D 20 25 64 20 25 64 0A 00 25 64 0A 00 25 64 2E
			0A 00 00 00 00 25 64 2E 0A 00 00 00 00 25 64 2E
			0A 00 00 00 00 25 64 20 2D 20 25 64 0A 00 00 00
			00 25 64 20 2D 20 25 64 }

	condition:
		uint16(0)==0x5a4d and filesize <50KB and $s1
}
