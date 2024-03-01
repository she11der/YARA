import "pe"

rule SIGNATURE_BASE_EQGRP_Tinyexec : FILE
{
	meta:
		description = "EQGRP Toolset Firewall - from files tinyexec"
		author = "Florian Roth (Nextron Systems)"
		id = "b783bafd-52e2-59e8-98ab-47de3250415e"
		date = "2016-08-16"
		modified = "2023-12-05"
		reference = "Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_eqgrp.yar#L1245-L1258"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "19b8d7e946d72424f81cd48ad4bf8791bf50a4cc146866e55ad501443a8d1e45"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = { 73 68 73 74 72 74 61 62 00 2E 74 65 78 74 }
		$s2 = { 5A 58 55 52 89 E2 55 50 89 E1 }

	condition:
		uint32(0)==0x464c457f and filesize <270 and all of them
}
