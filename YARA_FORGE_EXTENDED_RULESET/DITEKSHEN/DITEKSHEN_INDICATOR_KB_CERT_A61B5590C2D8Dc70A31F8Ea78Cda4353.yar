import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_A61B5590C2D8Dc70A31F8Ea78Cda4353 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "0a22b3a5-cc61-5aec-9fc7-bbd03cd4ab03"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L3243-L3254"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "7d57f5cb2691d8dfb5f5ef63f7bfb4290f0bd8d990c61fe0655e35c1b3f554f0"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "d1f77736e8594e026f67950ca2bf422bb12abc3a"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Bdddcfaebffbfdcabaffe" and pe.signatures[i].serial=="a6:1b:55:90:c2:d8:dc:70:a3:1f:8e:a7:8c:da:43:53")
}
