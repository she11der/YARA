import "pe"

rule RUSSIANPANDA_Andeloader
{
	meta:
		description = "Detects Ande Loader"
		author = "RussianPanda"
		id = "c08d63b6-9fef-505d-9611-9dd0403c7c7c"
		date = "2023-12-11"
		modified = "2023-12-11"
		reference = "https://github.com/RussianPanda95/Yara-Rules"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/1f0985c563eef9f1cda476556d29082a25bee0b3/AndeLoader/ande_loader.yar#L3-L18"
		license_url = "N/A"
		logic_hash = "cd55153077e5cfbd84cbe5b062dbd842def245417acfea4ed6c2b1db702dcc81"
		score = 75
		quality = 83
		tags = ""

	strings:
		$s1 = {59 61 6E 6F 41 74 74 72 69 62 75 74 65}
		$s2 = "CreateShortcut" wide
		$s3 = ".vbs" wide

	condition:
		3 of ($s*) and pe.imports("mscoree.dll")
}
