import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_C51F4Cf4D82Bc920421E1Ad93E39D490 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "cbb6cb90-b0f0-5271-81ae-8639c28a5df1"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L8731-L8744"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "b9152998eb3c4ba2b6e7571ed03c63ae1ade2f922df6901f8e46b08f41474f7b"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "d17dc7ef018e13b9a482b60871e25447fb1ae724dfe69b5287dce6b9b78d84a9"
		reason = "Quakbot"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "CUT AHEAD LTD" and pe.signatures[i].serial=="c5:1f:4c:f4:d8:2b:c9:20:42:1e:1a:d9:3e:39:d4:90")
}
