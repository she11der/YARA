rule RUSSIANPANDA_Obfuscation_Powershell_Special_Chars
{
	meta:
		description = "Detects PowerShell special character obfuscation"
		author = "RussianPanda"
		id = "1f2c116a-d93b-5a52-830a-d72ab2b4333f"
		date = "2024-01-12"
		modified = "2024-01-12"
		reference = "https://perl-users.jp/articles/advent-calendar/2010/sym/11"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/1a5f7fbf0094a17dcddaa74b56fb43a231b550af/PowerShell Obfuscation/obfuscation_powershell_special_chars.yar#L1-L14"
		license_url = "N/A"
		hash = "d77efad78ef3afc5426432597ba129141952719846bc5ccd058249bb23d8a905"
		logic_hash = "9a37be35d11c9ab7addef5b6af12ced387e524fbc79d63a03cf1b93e9c8aaaa5"
		score = 75
		quality = 81
		tags = ""

	strings:
		$s1 = {7d 3d 2b 2b 24 7b}
		$s2 = {24 28 20 20 29}
		$s3 = {24 7b [1-10] 7d 20 20 2b 20 20 24}

	condition:
		2 of ($s*)
}
