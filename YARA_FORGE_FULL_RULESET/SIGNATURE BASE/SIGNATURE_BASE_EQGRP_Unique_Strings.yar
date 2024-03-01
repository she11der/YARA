import "pe"

rule SIGNATURE_BASE_EQGRP_Unique_Strings
{
	meta:
		description = "EQGRP Toolset Firewall - Unique strings"
		author = "Florian Roth (Nextron Systems)"
		id = "08f5f1e3-ce4e-54ef-922f-50446edfcd70"
		date = "2016-08-16"
		modified = "2023-12-05"
		reference = "Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp.yar#L1292-L1305"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "070358ec9cccb5d9daa4e5a016d4f9a988b600d675484f06dc9a897cadf7af0c"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "/BananaGlee/ELIGIBLEBOMB" ascii
		$s2 = "Protocol must be either http or https (Ex: https://1.2.3.4:1234)"

	condition:
		1 of them
}
