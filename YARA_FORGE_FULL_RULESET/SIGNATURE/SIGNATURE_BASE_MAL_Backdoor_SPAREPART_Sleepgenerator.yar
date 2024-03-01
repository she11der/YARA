rule SIGNATURE_BASE_MAL_Backdoor_SPAREPART_Sleepgenerator
{
	meta:
		description = "Detects the algorithm used to determine the next sleep timer"
		author = "Mandiant"
		id = "b9cd46e4-0e06-5ead-8379-adcfc3c384d0"
		date = "2022-12-14"
		modified = "2023-12-05"
		reference = "https://www.mandiant.com/resources/blog/trojanized-windows-installers-ukrainian-government"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/mal_ru_sparepart_dec22.yar#L2-L20"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "f9cd5b145e372553dded92628db038d8"
		logic_hash = "41a9fdb2ba7aefcaf6ef2477b598e98b9045ef17ce9bfe46f3169d0b2e0dd289"
		score = 50
		quality = 85
		tags = ""
		version = "1"
		weight = "100"
		disclaimer = "This rule is meant for hunting and is not tested to run in a production environment."

	strings:
		$ = {C1 E8 06 89 [5] C1 E8 02 8B}
		$ = {c1 e9 03 33 c1 [3] c1 e9 05 33 c1 83 e0 01}
		$ = {8B 80 FC 00 00 00}
		$ = {D1 E8 [4] c1 E1 0f 0b c1}

	condition:
		all of them
}
