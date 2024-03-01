import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_19Beff8A6C129663E5E8C18953Dc1F67 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "8bc27a0c-898d-510f-ad9d-78d5bab40cad"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L4804-L4815"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "e62c4ab0652f872887b7bedadba3306c831351f57bc4a177302b1268d823f9f4"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "ad3deacd821fee3bb158665bd7fa491e39aab2e6"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "CULNADY LTD LTD" and pe.signatures[i].serial=="19:be:ff:8a:6c:12:96:63:e5:e8:c1:89:53:dc:1f:67")
}
