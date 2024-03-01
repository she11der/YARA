import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_03B27D7F4Ee21A462A064A17Eef70D6C : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "96920ba8-b6d6-5cf4-9a3c-cb6f5c9b3048"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L5270-L5281"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "53a4c4474b1add510624e23eac642e8cba145248d72a2ffc37d0aca141a041c2"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "a278b5c8a9798ee3b3299ec92a4ab618016628ee"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "CCL TRADING LIMITED" and pe.signatures[i].serial=="03:b2:7d:7f:4e:e2:1a:46:2a:06:4a:17:ee:f7:0d:6c")
}
