import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_2F38De4Ced0B070973B9E9B9B1Dcfa7F : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "39910712-4a11-5722-9b48-c069bfcefb14"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L8221-L8234"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "84c3d89e8393bcaddea53326730d795f482ec65c574fde5c1c81f395178b591a"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "71382f6c6e48df51f15606380cd6948bf37f044d18566ebc2d262fc87e70b9b1"
		reason = "Gh0stRAT"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Fahad Malik" and pe.signatures[i].serial=="2f:38:de:4c:ed:0b:07:09:73:b9:e9:b9:b1:dc:fa:7f")
}
