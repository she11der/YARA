rule RUSSIANPANDA_Vidar_DLL_Embedded
{
	meta:
		description = "Vidar Stealer with embedded DLL dependencies"
		author = "RussianPanda"
		id = "462fe42a-2504-5e7e-ad90-2c7e54478204"
		date = "2023-05-02"
		modified = "2023-05-05"
		reference = "https://github.com/RussianPanda95/Yara-Rules"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/1a5f7fbf0094a17dcddaa74b56fb43a231b550af/VidarStealer/vidar_ver3.6_3.7_dll_embedded.yar#L1-L21"
		license_url = "N/A"
		logic_hash = "98d23523c2ab196f670dc33164954fc69a1c1692fa870a476e25d7dd3cebace2"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s = {50 4B 03 04 14 00 00 00 08 00 24 56 25 55 2B 6D 5C 08 39 7C 05}
		$a1 = "https://t.me/mastersbots"
		$a2 = "https://steamcommunity.com/profiles/76561199501059503"
		$a3 = "%s\\%s\\Local Storage\\leveldb"
		$a4 = "\\Autofill\\%s_%s.txt"
		$a5 = "\\Downloads\\%s_%s.txt"
		$a6 = "\\CC\\%s_%s.txt"
		$a7 = "Exodus\\exodus.wallet"

	condition:
		$s and 5 of ($a*)
}