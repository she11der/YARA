import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_65Efa92A4164A3A2D888B5Cf8Ff073C8 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "07392a87-7d81-58c1-8dd6-2a9cbc8caa6b"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L6294-L6305"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "189f154d5b71bea9c06cd2c79d2460a1fb8cc9e0670a9ef8545e3abad80c8a06"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "928246cd6a0ee66095a43ae06a696b4c63c6ac24"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Ghisler Software GmbH" and pe.signatures[i].serial=="65:ef:a9:2a:41:64:a3:a2:d8:88:b5:cf:8f:f0:73:c8")
}
