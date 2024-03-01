rule DITEKSHEN_INDICATOR_KB_ID_Ransomware_Diavol
{
	meta:
		description = "Detects files referencing identities associated with Diavol ransomware"
		author = "ditekShen"
		id = "ea499318-ed5b-5597-8f9f-4ece7942cf4b"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_id.yar#L482-L491"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "c72f4d7854f7ba813c4872d47aad69edb8c2927f380b9213ced1aca52454eee5"
		score = 75
		quality = 71
		tags = ""

	strings:
		$s1 = "/noino.5fws6uqv5byttg2r//:sptth" ascii wide nocase
		$s2 = "https://r2gttyb5vqu6swf5.onion/" ascii wide nocase

	condition:
		any of them
}
