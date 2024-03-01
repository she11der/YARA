import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_35590Ebe4A02Dc23317D8Ce47A947A9B : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "36630916-26df-5d2c-8faf-9fa2e240bff3"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L2326-L2337"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "c01f9ecb1e69f6d0cb8061930cda27469eb18be19c0471192b31d516cddf828f"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "d9b60a67cf3c8964be1e691d22b97932d40437bfead97a84c1350a2c57914f28"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "OOO Largos" and pe.signatures[i].serial=="35:59:0e:be:4a:02:dc:23:31:7d:8c:e4:7a:94:7a:9b")
}
