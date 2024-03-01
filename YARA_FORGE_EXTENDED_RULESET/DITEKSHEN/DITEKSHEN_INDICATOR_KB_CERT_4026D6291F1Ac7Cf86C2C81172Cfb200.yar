import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_4026D6291F1Ac7Cf86C2C81172Cfb200 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "ea11705d-37a1-5050-b01a-b7fc523c675a"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L5218-L5229"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "c821f288bb6555e3955dfccf02edde2448f0499942eea24c488a6426985bff74"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "2ae4328db08bac015d8965e325b0263c0809d93e"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "MztxUCVYqnxgsyqVryViRnMfHFYBgyVMXkXuVGqmyPx" and pe.signatures[i].serial=="40:26:d6:29:1f:1a:c7:cf:86:c2:c8:11:72:cf:b2:00")
}
