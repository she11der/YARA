import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_690910Dc89D7857C3500Fb74Bed2B08D : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "d10931e2-8abb-592b-a070-3767f286bd74"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L1741-L1752"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "62a1be8435f73f3768030feb6b5917d9a8075e7abac52e654231ba9d16ccc374"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "dfeb986812ba9f2af6d4ff94c5d1128fa50787951c07b4088f099a5701f1a1a4"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "OLIMP STROI" and pe.signatures[i].serial=="69:09:10:dc:89:d7:85:7c:35:00:fb:74:be:d2:b0:8d")
}
