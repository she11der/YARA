rule SIGNATURE_BASE_APT_MAL_Wildneutron_Javacpl : FILE
{
	meta:
		description = "Wild Neutron APT Sample Rule"
		author = "Florian Roth (Nextron Systems)"
		id = "de82827e-61d4-559e-886a-78d5293ab141"
		date = "2015-07-10"
		modified = "2023-01-06"
		old_rule_name = "WildNeutron_javacpl"
		reference = "https://securelist.com/blog/research/71275/wild-neutron-economic-espionage-threat-actor-returns-with-new-tricks/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_wildneutron.yar#L272-L300"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "c9cb6ab956d29df9f59520262ab308a0256747cc3c898979347304950e093098"
		score = 60
		quality = 85
		tags = "FILE"
		hash1 = "683f5b476f8ffe87ec22b8bab57f74da4a13ecc3a5c2cbf951999953c2064fc9"
		hash2 = "758e6b519f6c0931ff93542b767524fc1eab589feb5cfc3854c77842f9785c92"
		hash3 = "8ca7ed720babb32a6f381769ea00e16082a563704f8b672cb21cf11843f4da7a"

	strings:
		$s1 = "RunFile: couldn't find ShellExecuteExA/W in SHELL32.DLL!" ascii fullword
		$s2 = "cmdcmdline" wide fullword
		$s3 = "\"%s\" /K %s" wide fullword
		$s4 = "Process is not running any more" wide fullword
		$s5 = "dpnxfsatz" wide fullword
		$op1 = { ff d6 50 ff 15 ?? ?? 43 00 8b f8 85 ff 74 34 83 64 24 0c 00 e8 ?? ?? 02 00 }
		$op2 = { b8 02 00 00 00 01 45 80 01 45 88 6a 00 47 52 89 7d 8c 03 d8 }
		$op3 = { 8b c7 f7 f6 46 89 b5 c8 fd ff ff 0f b7 c0 8b c8 0f af ce 3b cf }

	condition:
		uint16(0)==0x5a4d and filesize <5MB and ( all of ($s*) or all of ($op*))
}
