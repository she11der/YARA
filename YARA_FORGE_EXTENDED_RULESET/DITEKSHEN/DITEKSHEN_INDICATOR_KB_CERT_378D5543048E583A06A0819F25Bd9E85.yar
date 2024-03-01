import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_378D5543048E583A06A0819F25Bd9E85 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "3525888c-9558-5164-b94e-b16511a5ea72"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L694-L705"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "29c6ae99675b8ab2c497faad71791c3fc018e92447bd96f5b2b3f426e1a1322b"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "cf933a629598e5e192da2086e6110ad1974f8ec3"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "KITTY'S LTD" and pe.signatures[i].serial=="37:8d:55:43:04:8e:58:3a:06:a0:81:9f:25:bd:9e:85")
}
