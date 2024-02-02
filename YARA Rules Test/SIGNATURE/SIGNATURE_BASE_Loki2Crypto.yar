rule SIGNATURE_BASE_Loki2Crypto
{
	meta:
		description = "Rule to detect hardcoded DH modulus used in 1996/1997 Loki2 sourcecode; #ifdef STRONG_CRYPTO /* 384-bit strong prime */"
		author = "Costin Raiu, Kaspersky Lab"
		id = "d67288f8-5205-5882-8dff-041d092eea4f"
		date = "2017-03-21"
		modified = "2023-12-05"
		reference = "https://en.wikipedia.org/wiki/Moonlight_Maze"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_moonlightmaze.yar#L82-L106"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "19fbd8cbfb12482e8020a887d6427315"
		hash = "ea06b213d5924de65407e8931b1e4326"
		hash = "14ecd5e6fc8e501037b54ca263896a11"
		hash = "e079ec947d3d4dacb21e993b760a65dc"
		hash = "edf900cebb70c6d1fcab0234062bfc28"
		logic_hash = "c2315dafb0ecb9e6babd526a028835f3513218c1e667c81088c49ad13dbab5be"
		score = 75
		quality = 85
		tags = ""
		version = "1.0"

	strings:
		$modulus = {DA E1 01 CD D8 C9 70 AF C2 E4 F2 7A 41 8B 43 39 52 9B 4B 4D E5 85 F8 49}

	condition:
		( any of them )
}