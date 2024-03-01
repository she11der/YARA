import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00E161F76Da3B5E4623892C8E6Fda1Ea3D : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "a010cf24-b29a-5613-8122-92ced507564f"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L3789-L3800"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "7aae91e2873633989b3716930354361ee56d7fd7af35e105ae15ed6bf87de67a"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "df5fbfbfd47875b580b150603de240ead9c7ad27"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "TGN Nedelica d.o.o." and pe.signatures[i].serial=="00:e1:61:f7:6d:a3:b5:e4:62:38:92:c8:e6:fd:a1:ea:3d")
}
