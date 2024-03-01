import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_3Fd3661533Eef209153C9Afec3Ba4D8A : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "d47bc223-f29e-54d3-a452-064f89fa80f7"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L5617-L5628"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "e9662abf4c70d54fc719850ef216352fd59a559726fbad5db9e265660400b432"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "20ddd23f53e1ac49926335ec3e685a515ab49252"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SFB Regnskabsservice ApS" and pe.signatures[i].serial=="3f:d3:66:15:33:ee:f2:09:15:3c:9a:fe:c3:ba:4d:8a")
}
