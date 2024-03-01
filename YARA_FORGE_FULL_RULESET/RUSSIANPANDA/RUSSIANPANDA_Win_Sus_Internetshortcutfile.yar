rule RUSSIANPANDA_Win_Sus_Internetshortcutfile
{
	meta:
		description = "Detects suspicious Internet Shortcut Files that are often used to retrieve malware"
		author = "RussianPanda"
		id = "88d5d33f-0342-5575-b5e4-31ac5695abf2"
		date = "2024-02-17"
		modified = "2024-02-17"
		reference = "https://github.com/RussianPanda95/Yara-Rules"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/1f0985c563eef9f1cda476556d29082a25bee0b3/Techniques/win_sus_InternetShortcutFile.yar#L1-L19"
		license_url = "N/A"
		logic_hash = "9ec321ba521949fcc1db09b843913424182bfbb14eac61e92b7132d88b275ceb"
		score = 65
		quality = 58
		tags = ""

	strings:
		$s1 = "[InternetShortcut]"
		$s2 = {55 52 4C 3D 66 69 6C 65 3A 2F 2F}
		$a1 = ".exe"
		$a2 = ".dll"
		$a3 = ".js"
		$a4 = ".msi"
		$a5 = ".msix"
		$a6 = ".bat"
		$a7 = ".cmd"

	condition:
		all of ($s*) and any of ($a*)
}
