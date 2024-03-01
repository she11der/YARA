import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_539015999E304A5952985A994F9C3A53 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "b53f5843-fb4c-5c61-be24-21bdbc445239"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L2391-L2402"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "72304761de1d5e81659487947a1cfa017f7f41d5639f18634db4dfd094980518"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "7731825aea38cfc77ba039a74417dd211abef2e16094072d8c2384af1093f575"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Service lab LLC" and pe.signatures[i].serial=="53:90:15:99:9e:30:4a:59:52:98:5a:99:4f:9c:3a:53")
}
