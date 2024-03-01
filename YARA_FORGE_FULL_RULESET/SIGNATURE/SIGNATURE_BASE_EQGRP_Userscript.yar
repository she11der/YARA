import "pe"

rule SIGNATURE_BASE_EQGRP_Userscript
{
	meta:
		description = "EQGRP Toolset Firewall - file userscript.FW"
		author = "Florian Roth (Nextron Systems)"
		id = "c6c1b70e-437f-50e7-9055-b943a1a62e6c"
		date = "2016-08-16"
		modified = "2023-12-05"
		reference = "Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp.yar#L490-L503"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "718ee434c8ae61e2709df6dd431dbb0a2230085f0132ae82c7ceda4de75248cf"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "5098ff110d1af56115e2c32f332ff6e3973fb7ceccbd317637c9a72a3baa43d7"

	strings:
		$x1 = "Are you sure? Don't forget that NETSCREEN firewalls require BANANALIAR!! " fullword ascii

	condition:
		1 of them
}
