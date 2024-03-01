import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_0406C4A1521A38C8D0C4Aa214388E4Dc : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "108dd1b8-110a-5680-bd96-5517392300fa"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L8911-L8924"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "3db3a4f424d2974b746b8290a461f777eb88e0d8c6048e6e51e561c1f91b7747"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "7d6dc731d94c9aaf241f3df940ce8ca8393380b12f92e872273ae747c5d4791f"
		reason = "IcedID"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Venezia Design SRL" and pe.signatures[i].serial=="04:06:c4:a1:52:1a:38:c8:d0:c4:aa:21:43:88:e4:dc")
}
