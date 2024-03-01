import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_69A72F5591Ad78A0825Fbb9402Ab9543 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "a30ca6aa-3bf4-5fa2-8297-7b983410e5d4"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L8746-L8759"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "b2a8c08a612f7352a159a9d3f7d9152d9de043db1ec69e4bb2493533453f8f5c"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "42a6612f4c652b521435989b5f044403649fef6db4fb476f3c4d981dc2f9bdf8"
		reason = "Quakbot"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "PUSH BANK LIMITED" and pe.signatures[i].serial=="69:a7:2f:55:91:ad:78:a0:82:5f:bb:94:02:ab:95:43")
}
