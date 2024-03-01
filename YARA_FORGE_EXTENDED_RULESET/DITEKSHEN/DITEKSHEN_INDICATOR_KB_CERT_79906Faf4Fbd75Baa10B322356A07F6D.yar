import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_79906Faf4Fbd75Baa10B322356A07F6D : FILE
{
	meta:
		description = "Detects NetSupport (client) signed executables"
		author = "ditekSHen"
		id = "afca727c-ff08-5e47-9ef4-4cd2af96d294"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L7211-L7222"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "59862f31d0ba0cf56a93a86783ad802ea2e511845ab1d141aa224c0c61b720a7"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "f84ec9488bdac5f90db3c474b55e31a8f10a2026"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "NetSupport Ltd" and pe.signatures[i].serial=="79:90:6f:af:4f:bd:75:ba:a1:0b:32:23:56:a0:7f:6d")
}
