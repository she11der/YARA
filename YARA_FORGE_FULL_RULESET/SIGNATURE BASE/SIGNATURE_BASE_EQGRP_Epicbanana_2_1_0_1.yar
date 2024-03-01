import "pe"

rule SIGNATURE_BASE_EQGRP_Epicbanana_2_1_0_1
{
	meta:
		description = "EQGRP Toolset Firewall - file epicbanana_2.1.0.1.py"
		author = "Florian Roth (Nextron Systems)"
		id = "cc3346bd-0347-5cf3-b946-5c017d68d93e"
		date = "2016-08-16"
		modified = "2023-12-05"
		reference = "Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp.yar#L385-L399"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "be0b180e0dfdda35725ac6d9c35752a0b56bdbdaf985b6932c7d2ff342d4cde3"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "4b13cc183c3aaa8af43ef3721e254b54296c8089a0cd545ee3b867419bb66f61"

	strings:
		$s1 = "failed to create version-specific payload" fullword ascii
		$s2 = "(are you sure you did \"make [version]\" in versions?)" fullword ascii

	condition:
		1 of them
}
