import "pe"

rule SIGNATURE_BASE_EQGRP_Eligiblebombshell_Generic : FILE
{
	meta:
		description = "EQGRP Toolset Firewall - from files eligiblebombshell_1.2.0.1.py, eligiblebombshell_1.2.0.1.py"
		author = "Florian Roth (Nextron Systems)"
		id = "7abe53f6-9880-523a-b71f-6e3850047764"
		date = "2016-08-16"
		modified = "2023-12-05"
		reference = "Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp.yar#L1201-L1218"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "a2e13300736f99aff30c7b4f7f0b148d62ecb1e72435a3e15e4f85b30d904ffd"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash1 = "dd0e3ae6e1039a755bf6cb28bf726b4d6ab4a1da2392ba66d114a43a55491eb1"
		hash2 = "dd0e3ae6e1039a755bf6cb28bf726b4d6ab4a1da2392ba66d114a43a55491eb1"

	strings:
		$s1 = "logging.error(\"       Perhaps you should run with --scan?\")" fullword ascii
		$s2 = "logging.error(\"ERROR: No entry for ETag [%s] in %s.\" %" fullword ascii
		$s3 = "\"be supplied\")" fullword ascii

	condition:
		( filesize <70KB and 2 of ($s*)) or ( all of them )
}
