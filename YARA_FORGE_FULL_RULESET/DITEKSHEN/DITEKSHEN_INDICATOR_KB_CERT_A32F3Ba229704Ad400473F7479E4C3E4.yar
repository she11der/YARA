import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_A32F3Ba229704Ad400473F7479E4C3E4 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "28d687bc-e67c-51d1-82af-53255ee44a8d"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L7771-L7784"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "9c7b9b6827e10a8c2a6d771d14068a074104683fe75f24dea85c5bf3f3bc04db"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "ab4b30913895d8df383fdadebc29d2e04a5c854bc4172c0d41bcbef176e8f37e"
		reason = "RecordBreaker"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SOTUL SOLUTIONS LIMITED" and pe.signatures[i].serial=="a3:2f:3b:a2:29:70:4a:d4:00:47:3f:74:79:e4:c3:e4")
}
