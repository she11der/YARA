import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_063A7D09107Eddd8Aa1F733634C6591B : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "489daa61-8409-500d-bc46-a42a444fcdc0"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L2822-L2833"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "8b6c1935d51207e6b9919c85d369dcc6963f52ee4d21758d18e2c57115e9051b"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "a03f9b3f3eb30ac511463b24f2e59e89ee4c6d4a"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Smart Line Logistics" and pe.signatures[i].serial=="06:3a:7d:09:10:7e:dd:d8:aa:1f:73:36:34:c6:59:1b")
}
