import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_5Aa94583A95D42F1 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "a77e58c7-c613-5416-9bcd-336c036d99bd"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L7017-L7028"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "174ce032fd87028e34843417d5a4695d6d6e2eb444095e005588f1acf291cdf8"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "0b27715d7c78368bca3ac0bb829a7ceb19b3b5c3"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "UInt32" and pe.signatures[i].serial=="5a:a9:45:83:a9:5d:42:f1")
}
