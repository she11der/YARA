rule DITEKSHEN_INDICATOR_KB_ID_Ransomware_Cryptomix
{
	meta:
		description = "Detects files referencing identities associated with CryptoMix ransomware"
		author = "ditekShen"
		id = "7e623d06-36e8-576d-b261-d562eccf549b"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_id.yar#L108-L123"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "27b75a476229fc877c316f7a61d1ed647f5a67ac44a174d86c084063f039b20c"
		score = 75
		quality = 34
		tags = ""

	strings:
		$s1 = "portstatrelea1982@protonmail.om" ascii wide nocase
		$s2 = "unlock@eqaltech.su" ascii wide nocase
		$s3 = "unlock@royalmail.su" ascii wide nocase
		$s4 = "adexsin276@gmail.com" ascii wide nocase
		$s5 = "nbactocepnyou@protonmail.com" ascii wide nocase
		$s6 = "nunlock@eqaltech.su" ascii wide nocase
		$s7 = "nsnlock@royalmail.su" ascii wide nocase
		$s8 = "cersiacsofal@protonmail.com" ascii wide nocase

	condition:
		any of them
}
