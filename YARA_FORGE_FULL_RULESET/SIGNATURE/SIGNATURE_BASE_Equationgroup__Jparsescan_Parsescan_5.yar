rule SIGNATURE_BASE_Equationgroup__Jparsescan_Parsescan_5 : FILE
{
	meta:
		description = "Equation Group hack tool leaked by ShadowBrokers- from files jparsescan, parsescan"
		author = "Florian Roth (Nextron Systems)"
		id = "964a4e49-9163-5dd6-bb2c-88fa39d5f356"
		date = "2017-04-08"
		modified = "2023-12-05"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp_apr17.yar#L932-L950"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "719baa53db53f4cc4f3e9ed935814e42e5cb4b7fb8eaaa373feb73df69bfcde0"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash1 = "8c248eec0af04300f3ba0188fe757850d283de84cf42109638c1c1280c822984"
		hash2 = "942c12067b0afe9ebce50aa9dfdbf64e6ed0702d9a3a00d25b4fca62a38369ef"

	strings:
		$s1 = "# default is to dump out all scanned hosts found" fullword ascii
		$s2 = "$bool .= \" -r \" if (/mibiisa.* -r/);" fullword ascii
		$s3 = "sadmind is available on two ports, this also works)" fullword ascii
		$s4 = "-x IP      gives \\\"hostname:# users:load ...\\\" if positive xwin scan" fullword ascii

	condition:
		( uint16(0)==0x2123 and filesize <40KB and 1 of them ) or (2 of them )
}
