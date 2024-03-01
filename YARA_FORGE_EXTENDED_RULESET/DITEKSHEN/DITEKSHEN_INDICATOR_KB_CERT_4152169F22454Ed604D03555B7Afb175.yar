import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_4152169F22454Ed604D03555B7Afb175 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "61286549-7561-5607-9073-2a3ee0d54a44"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L1793-L1804"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "ee965ee8b6ebbb6171e3b10a7887acf35c9ed7fcbe49b7f403190c7fb046ec63"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "a1561cacd844fcb62e9e0a8ee93620b3b7d4c3f4bd6f3d6168129136471a7fdb"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SMACKTECH SOFTWARE LIMITED" and pe.signatures[i].serial=="41:52:16:9f:22:45:4e:d6:04:d0:35:55:b7:af:b1:75")
}
