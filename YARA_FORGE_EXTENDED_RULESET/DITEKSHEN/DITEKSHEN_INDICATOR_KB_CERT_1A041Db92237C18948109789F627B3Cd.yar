import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_1A041Db92237C18948109789F627B3Cd : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "0a5a6b19-0fbe-5e0c-bfb1-ca201207f6c7"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L7308-L7320"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "f5e07eb58a68dea062522869c43daeddab666f12b078a4f2ce9aa37885e46cbd"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "2315cf802aaf96d11f18766315239016e533bf32"
		hash1 = "a0338becbfe808bc7655d8b6c825e2e99b37945e5d8fc43a83aec479d64f422d"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Amitotic" and pe.signatures[i].serial=="1a:04:1d:b9:22:37:c1:89:48:10:97:89:f6:27:b3:cd")
}
