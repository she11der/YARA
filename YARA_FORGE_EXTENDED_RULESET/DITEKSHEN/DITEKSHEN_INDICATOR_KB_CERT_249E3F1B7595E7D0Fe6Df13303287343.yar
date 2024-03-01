import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_249E3F1B7595E7D0Fe6Df13303287343 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "3f780428-a482-5201-a7ca-d3608779a5e4"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L5007-L5018"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "4df122a53f2c1a08d1694c8e64b802f58507bb985f1aed8c91e6d7ad24906fca"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "8e99b2786f59e543d1f3d02d140e35342c55c18a"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "gsLPuSUgRZueWihiZHqYBriNSQqS" and pe.signatures[i].serial=="24:9e:3f:1b:75:95:e7:d0:fe:6d:f1:33:03:28:73:43")
}
