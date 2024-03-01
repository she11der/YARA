import "pe"

rule SIGNATURE_BASE_EQGRP_Jetplow_SH
{
	meta:
		description = "EQGRP Toolset Firewall - file jetplow.sh"
		author = "Florian Roth (Nextron Systems)"
		id = "e7780540-29c9-5827-8ac0-a685d9ba8a5f"
		date = "2016-08-16"
		modified = "2023-12-05"
		reference = "Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_eqgrp.yar#L650-L666"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "8ae203527c4e41ae169c63521bb08d5199c43dfd1028574a1791ab1f8f198105"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "ee266f84a1a4ccf2e789a73b0a11242223ed6eba6868875b5922aea931a2199c"

	strings:
		$s1 = "cd /current/bin/FW/BANANAGLEE/$bgver/Install/LP/jetplow" fullword ascii
		$s2 = "***** Please place your UA in /current/bin/FW/OPS *****" fullword ascii
		$s3 = "ln -s ../jp/orig_code.bin orig_code_pixGen.bin" fullword ascii
		$s4 = "*****             Welcome to JetPlow              *****" fullword ascii

	condition:
		1 of them
}
