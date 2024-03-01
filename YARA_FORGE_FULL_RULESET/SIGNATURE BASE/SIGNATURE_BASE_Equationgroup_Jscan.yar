rule SIGNATURE_BASE_Equationgroup_Jscan : FILE
{
	meta:
		description = "Equation Group hack tool leaked by ShadowBrokers- file jscan"
		author = "Florian Roth (Nextron Systems)"
		id = "c4cebc69-8ec8-5ad7-bd93-55565b3eb92b"
		date = "2017-04-08"
		modified = "2023-12-05"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp_apr17.yar#L632-L646"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "d3bbdb90da9fa5b8b41a8b5d35a9b42e4fa15f291146575b0ef22e81441dcbde"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "8075f56e44185e1be26b631a2bad89c5e4190c2bfc9fa56921ea3bbc51695dbe"

	strings:
		$s1 = "$scanth = $scanth . \" -s \" . $scanthreads;" fullword ascii
		$s2 = "print \"java -jar jscanner.jar$scanth$list\\n\";" fullword ascii

	condition:
		filesize <250KB and 1 of them
}
