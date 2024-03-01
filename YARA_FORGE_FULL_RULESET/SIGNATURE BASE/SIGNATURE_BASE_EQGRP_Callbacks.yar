import "pe"

rule SIGNATURE_BASE_EQGRP_Callbacks
{
	meta:
		description = "EQGRP Toolset Firewall - Callback addresses"
		author = "Florian Roth (Nextron Systems)"
		id = "dd1fbe09-4def-562d-825d-e790dc2c3dd9"
		date = "2016-08-16"
		modified = "2023-12-05"
		reference = "Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp.yar#L1260-L1272"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "34881cf8f9f29482a1e129f0f61470d4cc3fa6b78b9f6dda25862371896deca7"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "30.40.50.60:9342" fullword ascii wide

	condition:
		1 of them
}
