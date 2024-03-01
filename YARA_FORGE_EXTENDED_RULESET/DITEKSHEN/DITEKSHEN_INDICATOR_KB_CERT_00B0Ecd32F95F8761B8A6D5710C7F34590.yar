import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00B0Ecd32F95F8761B8A6D5710C7F34590 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "2535c9eb-ed4a-52b9-8ad5-80c44c035135"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L1140-L1151"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "5c181dab1f39138c67650d6654353de2be29cdbf45e0f5235776d28d40194f24"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "2e25e7e8abc238b05de5e2a482e51ed324fbaa76"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "\\xE6\\x96\\xAF\\xD0\\xA8\\xD0\\xA8\\xE5\\xBC\\x97\\xE6\\xAF\\x94\\xE5\\xBC\\x97\\xD0\\xA8\\xE6\\xAF\\x94\\xD0\\xA8\\xE5\\xBC\\x97\\xD0\\xA8\\xE5\\xB0\\x94\\xE5\\xBC\\x97\\xE5\\xBC\\x97\\xD0\\xA8\\xE5\\xB0\\x94\\xD0\\xA8\\xE6\\x96\\xAF\\xE5\\xB0\\x94\\xE5\\xBC\\x97" and pe.signatures[i].serial=="00:b0:ec:d3:2f:95:f8:76:1b:8a:6d:57:10:c7:f3:45:90")
}
