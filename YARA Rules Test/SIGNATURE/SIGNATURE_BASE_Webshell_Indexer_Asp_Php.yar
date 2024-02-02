rule SIGNATURE_BASE_Webshell_Indexer_Asp_Php
{
	meta:
		description = "PHP Webshells Github Archive - file indexer.asp.php.txt"
		author = "Florian Roth (Nextron Systems)"
		id = "d6e17429-1b58-5a1b-846d-f5dbfd74cf3a"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L5646-L5662"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "e9a7aa5eb1fb228117dc85298c7d3ecd8e288a2d"
		logic_hash = "c576925c95b5bd2549e8039a1fc6ac228bfab5ddee8c4e12264ea78e9828ba5c"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "<meta http-equiv=\"Content-Language\" content=\"tr\">" fullword
		$s1 = "<title>WwW.SaNaLTeRoR.OrG - inDEXER And ReaDer</title>" fullword
		$s2 = "<form action=\"?Gonder\" method=\"post\">" fullword
		$s4 = "<form action=\"?oku\" method=\"post\">" fullword
		$s7 = "var message=\"SaNaLTeRoR - " fullword
		$s8 = "nDexEr - Reader\"" fullword

	condition:
		3 of them
}