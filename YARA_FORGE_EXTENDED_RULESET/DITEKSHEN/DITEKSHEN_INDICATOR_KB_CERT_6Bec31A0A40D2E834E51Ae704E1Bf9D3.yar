import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_6Bec31A0A40D2E834E51Ae704E1Bf9D3 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "9228c13e-b380-5867-ad1f-e483c8977196"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L6538-L6549"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "f1fdd6e76deea106db9fc4ef0916b2cecd6edb3849847946f15c194a9028a76e"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "7a236872302156c58d493b63a1607a09c4f1d0b8"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "whatsupfuckers" and pe.signatures[i].serial=="6b:ec:31:a0:a4:0d:2e:83:4e:51:ae:70:4e:1b:f9:d3")
}
