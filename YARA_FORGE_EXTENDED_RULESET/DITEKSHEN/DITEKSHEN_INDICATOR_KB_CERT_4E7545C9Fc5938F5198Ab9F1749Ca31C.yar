import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_4E7545C9Fc5938F5198Ab9F1749Ca31C : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "af27fbf7-f4e2-59e9-8b2b-b353704ce9d6"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L5445-L5456"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "4b7bc07622ad3f7ec77f4bb0d51350c82734af4b73a26ecd21955e55e99bb515"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "7a49677c535a13d0a9b6deb539d084ff431a5b54"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "For M d.o.o." and pe.signatures[i].serial=="4e:75:45:c9:fc:59:38:f5:19:8a:b9:f1:74:9c:a3:1c")
}
