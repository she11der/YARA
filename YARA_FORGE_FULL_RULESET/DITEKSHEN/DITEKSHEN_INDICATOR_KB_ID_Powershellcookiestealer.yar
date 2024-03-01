rule DITEKSHEN_INDICATOR_KB_ID_Powershellcookiestealer
{
	meta:
		description = "Detects email accounts used for exfiltration observed in PowerShellCookieStealer"
		author = "ditekShen"
		id = "c2bbb9a8-3e4c-5676-9676-2708a196ef8d"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_id.yar#L706-L715"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "bd404e94939acb92dd56a7d2a1f7536bcb3f520ca1e9dc614b53828afbc6dac8"
		score = 75
		quality = 71
		tags = ""

	strings:
		$s1 = "senmn0w@gmail.com" ascii wide nocase
		$s2 = "mohamed.trabelsi.ena2@gmail.com" ascii wide nocase

	condition:
		any of them
}
