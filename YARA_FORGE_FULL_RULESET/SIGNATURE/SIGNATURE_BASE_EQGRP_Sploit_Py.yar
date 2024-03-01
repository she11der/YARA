import "pe"

rule SIGNATURE_BASE_EQGRP_Sploit_Py
{
	meta:
		description = "EQGRP Toolset Firewall - file sploit.py"
		author = "Florian Roth (Nextron Systems)"
		id = "9f403965-5fb1-55b2-bef6-65c18e08e58f"
		date = "2016-08-16"
		modified = "2023-12-05"
		reference = "Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp.yar#L727-L742"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "874eaffcbc191951db39ba6c85e8c80b83b0df8d33136b6cdcdefcb28e596474"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "0316d70a5bbf068a7fc791e08e816015d04ec98f088a7ff42af8b9e769b8d1f6"

	strings:
		$x1 = "the --spoof option requires 3 or 4 fields as follows redir_ip" ascii
		$x2 = "[-] timeout waiting for response - target may have crashed" fullword ascii
		$x3 = "[-] no response from health check - target may have crashed" fullword ascii

	condition:
		1 of them
}
