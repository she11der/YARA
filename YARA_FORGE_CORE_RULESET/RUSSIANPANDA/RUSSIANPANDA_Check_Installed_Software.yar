rule RUSSIANPANDA_Check_Installed_Software : FILE
{
	meta:
		description = "No description has been set in the source file - RussianPanda"
		author = "RussianPanda"
		id = "a45c7012-dc83-59da-a691-251f0a06be12"
		date = "2024-01-14"
		modified = "2024-01-15"
		reference = "https://unprotect.it/technique/checking-installed-software/"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/1a5f7fbf0094a17dcddaa74b56fb43a231b550af/Techniques/check_installed_software.yar#L1-L19"
		license_url = "N/A"
		hash = "db44d4cd1ea8142790a6b26880b41ee23de5db5c2a63afb9ee54585882f1aa07"
		logic_hash = "ab079f1edaffca5bce1e872d6e4fc44f7c22b9260feaed7cd38e578646d420ef"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$d1 = "DisplayVersion"
		$u1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"
		$reg = "RegOpenKeyExA"
		$h = {68 (01|02) 00 00 80}

	condition:
		uint16(0)==0x5A4D and $reg and $h and for any i in (1..#u1) : ($d1 in (@u1[i]-200..@u1[i]+200))
}
