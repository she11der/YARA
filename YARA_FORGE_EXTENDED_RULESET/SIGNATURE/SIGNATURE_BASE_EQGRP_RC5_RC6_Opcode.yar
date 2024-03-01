import "pe"

rule SIGNATURE_BASE_EQGRP_RC5_RC6_Opcode
{
	meta:
		description = "EQGRP Toolset Firewall - RC5 / RC6 opcode"
		author = "Florian Roth (Nextron Systems)"
		id = "b12a1a2c-8d32-5318-a658-6aa1a08c3263"
		date = "2016-08-17"
		modified = "2023-12-05"
		reference = "https://securelist.com/blog/incidents/75812/the-equation-giveaway/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_eqgrp.yar#L1307-L1326"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "a79208c5924e1d5cc9db922f80403514e516eadb725393c1ebc9a6236ca90b98"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = { 8B 74 91 FC 81 EE 47 86 C8 61 89 34 91 42 83 FA 2B }

	condition:
		1 of them
}
