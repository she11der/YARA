import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_066276Af2F2C7E246D3B1Cab1B4Aa42E : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "32b8e28b-361f-53e5-b06c-504dd9e86ae9"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L6405-L6416"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "2a554105ae99de388621adefb2f53d2d0873ac3175ca2ccf00fc6a498ea2fd29"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "dee5ca4be94a8737c85bbee27bd9d81b235fb700"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "IQ Trade ApS" and pe.signatures[i].serial=="06:62:76:af:2f:2c:7e:24:6d:3b:1c:ab:1b:4a:a4:2e")
}
