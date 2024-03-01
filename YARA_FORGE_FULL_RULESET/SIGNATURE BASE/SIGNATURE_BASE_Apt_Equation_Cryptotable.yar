rule SIGNATURE_BASE_Apt_Equation_Cryptotable
{
	meta:
		description = "Rule to detect the crypto library used in Equation group malware"
		author = "Kaspersky Lab"
		id = "e7f313a3-8ef8-5363-898a-836a96aaa2ff"
		date = "2015-02-16"
		modified = "2023-12-05"
		reference = "https://securelist.com/blog/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/spy_equation_fiveeyes.yar#L59-L71"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "e660fe423330334a1e3167d6a45e5ce2469fec276838618a7cb0340ec8172275"
		score = 75
		quality = 85
		tags = ""
		version = "1.0"

	strings:
		$a = {37 DF E8 B6 C7 9C 0B AE 91 EF F0 3B 90 C6 80 85 5D 19 4B 45 44 12 3C E2 0D 5C 1C 7B C4 FF D6 05 17 14 4F 03 74 1E 41 DA 8F 7D DE 7E 99 F1 35 AC B8 46 93 CE 23 82 07 EB 2B D4 72 71 40 F3 B0 F7 78 D7 4C D1 55 1A 39 83 18 FA E1 9A 56 B1 96 AB A6 30 C5 5F BE 0C 50 C1}

	condition:
		$a
}
