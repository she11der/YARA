import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_17D99Cc2F5B29522D422332E681F3E18 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "98493d50-2bee-50a5-93f3-851559c494a6"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L5152-L5163"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "95116d1114239795707b310afea3122d274dac471546de1e0147992d1f3a1d4f"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "969932039e8bf3b4c71d9a55119071cfa1c4a41b"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "PKV Trading ApS" and pe.signatures[i].serial=="17:d9:9c:c2:f5:b2:95:22:d4:22:33:2e:68:1f:3e:18")
}
