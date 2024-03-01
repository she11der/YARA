rule ELASTIC_Windows_Trojan_Redlinestealer_F54632Eb : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Redlinestealer (Windows.Trojan.RedLineStealer)"
		author = "Elastic Security"
		id = "f54632eb-2c66-4aff-802d-ad1c076e5a5e"
		date = "2021-06-12"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/84213d9b40fee553ea3065cb4bb057c7c1685b59/yara/rules/Windows_Trojan_RedLineStealer.yar#L29-L56"
		license_url = "https://github.com/elastic/protections-artifacts//blob/84213d9b40fee553ea3065cb4bb057c7c1685b59/LICENSE.txt"
		hash = "d82ad08ebf2c6fac951aaa6d96bdb481aa4eab3cd725ea6358b39b1045789a25"
		logic_hash = "1779919556ee5c9a78342aabafb8408e035cb39632b25c54da6bf195894901dc"
		score = 75
		quality = 50
		tags = "FILE, MEMORY"
		fingerprint = "6a9d45969c4d58181fca50d58647511b68c1e6ee1eeac2a1838292529505a6a0"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "ttp://checkip.amazonaws.com/logins.json" wide fullword
		$a2 = "https://ipinfo.io/ip%appdata%\\" wide fullword
		$a3 = "Software\\Valve\\SteamLogin Data" wide fullword
		$a4 = "get_ScannedWallets" ascii fullword
		$a5 = "get_ScanTelegram" ascii fullword
		$a6 = "get_ScanGeckoBrowsersPaths" ascii fullword
		$a7 = "<Processes>k__BackingField" ascii fullword
		$a8 = "<GetWindowsVersion>g__HKLM_GetString|11_0" ascii fullword
		$a9 = "<ScanFTP>k__BackingField" ascii fullword
		$a10 = "DataManager.Data.Credentials" ascii fullword

	condition:
		6 of ($a*)
}
