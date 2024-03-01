import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_Da20761Afbb0463C55B1Ea88Bbc7Ec57 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "63e4b8f6-64f1-58a2-920a-e1d4b113380b"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L8716-L8729"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "a4f6bb9742ab40e8003ea14f9645f0c7f885b461fbeb01164b86ddacbda1113f"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "f12dd6e77ffab75870b24dd5bfda5a360843f9e5591e764be9f0a2ac59a710d3"
		reason = "Quakbot"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "CLEVER CLOSE s.r.o." and pe.signatures[i].serial=="da:20:76:1a:fb:b0:46:3c:55:b1:ea:88:bb:c7:ec:57")
}
