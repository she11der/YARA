import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00Fed006Fbf85Cd1C6Ba6B4345B198E1E6 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "8f7d0337-7840-5c6e-b562-dbaef1a7c022"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L5432-L5443"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "26690cb1ef7eb9b7009376b4c2a30505f01184f4462478f65379372e84e02bc8"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "4bc67aca336287ff574978ef3bf67c688f6449f2"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "LoL d.o.o." and pe.signatures[i].serial=="00:fe:d0:06:fb:f8:5c:d1:c6:ba:6b:43:45:b1:98:e1:e6")
}
