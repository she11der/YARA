import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_2C1Ee9B583310B5E34A1Ee6945A34B26 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "0cc94ceb-a5bf-511a-bcd0-136b5d35c348"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L3672-L3683"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "4891757929b64b45591792dd2526ffb7588345f76bcbd3e47f567e72ba03d7f2"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "7af96a09b6c43426369126cfffac018f11e5562cb64d32e5140cff3f138ffea4"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "OOO Artmarket" and pe.signatures[i].serial=="2c:1e:e9:b5:83:31:0b:5e:34:a1:ee:69:45:a3:4b:26")
}
