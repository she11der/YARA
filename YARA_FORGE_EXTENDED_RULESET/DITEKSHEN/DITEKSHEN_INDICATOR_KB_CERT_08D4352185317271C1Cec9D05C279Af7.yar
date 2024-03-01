import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_08D4352185317271C1Cec9D05C279Af7 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "a0197037-874c-55e7-80aa-e8b7156a26a3"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L471-L482"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "6f4b8a52e152097a6e18f55b6b677eb1ba0f4da78ce68ffa35510bfb485e01e9"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "52fe4ecd6c925e89068fee38f1b9a669a70f8bab"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Retalit LLC" and pe.signatures[i].serial=="08:d4:35:21:85:31:72:71:c1:ce:c9:d0:5c:27:9a:f7")
}
