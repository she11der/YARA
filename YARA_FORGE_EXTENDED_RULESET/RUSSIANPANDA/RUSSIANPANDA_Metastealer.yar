import "pe"

rule RUSSIANPANDA_Metastealer
{
	meta:
		description = "Detects the old version of MetaStealer 11-2023"
		author = "RussianPanda"
		id = "c178630b-d188-5faf-86b3-436894241d77"
		date = "2023-11-16"
		modified = "2023-12-30"
		reference = "https://github.com/RussianPanda95/Yara-Rules"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/d6b1e8ac1e4cbf548804bd84e5f63f3f426b9738/MetaStealer/metastealer.yar#L2-L19"
		license_url = "N/A"
		logic_hash = "f78b376713daf82aa2e0cbd6bf45f33d25530449fa05673c8a7c6b4c0dddca79"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s1 = "FileScannerRule"
		$s2 = "MSObject"
		$s3 = "MSValue"
		$s4 = "GetBrowsers"
		$s5 = "Biohazard"

	condition:
		4 of ($s*) and pe.imports("mscoree.dll")
}
