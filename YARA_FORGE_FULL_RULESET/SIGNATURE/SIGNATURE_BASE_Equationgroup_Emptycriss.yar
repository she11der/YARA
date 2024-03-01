rule SIGNATURE_BASE_Equationgroup_Emptycriss : FILE
{
	meta:
		description = "Equation Group hack tool leaked by ShadowBrokers- file emptycriss"
		author = "Florian Roth (Nextron Systems)"
		id = "658a0a2c-ea3a-5531-abea-54f0ed786e79"
		date = "2017-04-08"
		modified = "2023-12-05"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp_apr17.yar#L15-L30"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "fcfbe4a8a959491dfba9e5d958e43221d83a1e49dcf005872a1b71efb1226d99"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "a698d35a0c4d25fd960bd40c1de1022bb0763b77938bf279e91c9330060b0b91"

	strings:
		$s1 = "./emptycriss <target IP>" fullword ascii
		$s2 = "Cut and paste the following to the telnet prompt:" fullword ascii
		$s8 = "environ define TTYPROMPT abcdef" fullword ascii

	condition:
		( filesize <50KB and 1 of them )
}
