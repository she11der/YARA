import "pe"

rule SIGNATURE_BASE_EQGRP_Mixtext
{
	meta:
		description = "EQGRP Toolset Firewall - file MixText.py"
		author = "Florian Roth (Nextron Systems)"
		id = "99b06100-8a05-5c22-8b7d-ed451d5f4e81"
		date = "2016-08-16"
		modified = "2023-12-05"
		reference = "Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp.yar#L284-L297"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "cae2437124ad6e69b04a1338b651e33c7358b7fedd0613f3fa1025cf980e14ab"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "e4d24e30e6cc3a0aa0032dbbd2b68c60bac216bef524eaf56296430aa05b3795"

	strings:
		$s1 = "BinStore enabled implants." fullword ascii

	condition:
		1 of them
}
