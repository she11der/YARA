import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_500D76B1B4Bfaf4A131F027668Fea2D3 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "670138fc-7f2f-5145-8488-196912292ef7"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L6268-L6279"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "a4f626e5ae9d273723814b0d944b067e70714e10776600a1bd0f90af31c1146a"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "fa491e71d98c7e598e32628a6272a005df86b196"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "FviSBJQX" and pe.signatures[i].serial=="50:0d:76:b1:b4:bf:af:4a:13:1f:02:76:68:fe:a2:d3")
}
