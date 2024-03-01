rule RUSSIANPANDA_Fakebat_Powershell
{
	meta:
		description = "Detects FakeBat PowerShell scripts"
		author = "RussianPanda"
		id = "76149a6f-c370-5e48-82cc-c89b545c0aa8"
		date = "2023-12-01"
		modified = "2023-12-01"
		reference = "https://github.com/RussianPanda95/Yara-Rules"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/1a5f7fbf0094a17dcddaa74b56fb43a231b550af/FakeBat/fakebat_powershell.yar#L1-L13"
		license_url = "N/A"
		logic_hash = "df6b30d97ac6c9b248fed0d901e8a0a6ad1d855483a5006b008b839d9961092a"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s1 = "$LoadDomen/?status=start&av=" nocase
		$s2 = "$xxx.gpg" nocase

	condition:
		all of ($s*)
}
