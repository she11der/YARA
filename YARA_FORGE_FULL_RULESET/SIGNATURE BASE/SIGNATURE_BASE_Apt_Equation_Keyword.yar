rule SIGNATURE_BASE_Apt_Equation_Keyword : FILE
{
	meta:
		description = "Rule to detect Equation group's keyword in executable file"
		author = "Florian Roth"
		id = "a7d4eda5-f390-5099-9c46-bf74a878b4f0"
		date = "2015-09-26"
		modified = "2023-12-05"
		reference = "http://securelist.com/blog/research/68750/equation-the-death-star-of-malware-galaxy/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/spy_equation_fiveeyes.yar#L592-L603"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "d9a2b31d078eabbc930e9ec06e5ead5a6cda4eebf1c0ebe8164caf75a9d3cba6"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$a1 = "Backsnarf_AB25" wide
		$a2 = "Backsnarf_AB25" ascii

	condition:
		uint16(0)==0x5a4d and 1 of ($a*)
}
