import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00Aebe117A13B8Bca21685Df48C74F584D : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "2b9c40e8-9c0e-523d-b746-4e31d0a780e0"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L4968-L4979"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "cb17c6f311d88125ad0c790c61fe0dd1ffbdefdbea45ffb54c47da5d98f99900"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "4dc9713dfb079fbae4173d342ebeb4efb9b0a4dc"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "NANAX d.o.o." and pe.signatures[i].serial=="00:ae:be:11:7a:13:b8:bc:a2:16:85:df:48:c7:4f:58:4d")
}
