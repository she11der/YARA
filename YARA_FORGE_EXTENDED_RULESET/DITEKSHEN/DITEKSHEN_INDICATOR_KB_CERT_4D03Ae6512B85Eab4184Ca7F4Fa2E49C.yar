import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_4D03Ae6512B85Eab4184Ca7F4Fa2E49C : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "a7dc0a07-f295-5aff-9df0-71f27f0fe88c"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L7184-L7196"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "2cbeaf65b0d3340df08baf67134a2fe0b26921f2e35ce541884209e3ecddf233"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "0215ff94a5c0d97db82e11f87e0dfb4318acac38"
		hash1 = "18bf017bdd74e8e8f5db5a4dd7ec3409021c7b0d2f125f05d728f3b740132015"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Lenovo IdeaCentre" and pe.signatures[i].serial=="4d:03:ae:65:12:b8:5e:ab:41:84:ca:7f:4f:a2:e4:9c")
}
