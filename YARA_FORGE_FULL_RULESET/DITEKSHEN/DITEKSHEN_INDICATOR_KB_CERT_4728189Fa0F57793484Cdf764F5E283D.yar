import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_4728189Fa0F57793484Cdf764F5E283D : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "02ec531e-aa1b-50b8-ae32-d885a0185cfe"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L8326-L8339"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "181971946ee4d643430b733ed57ccf07c940205853c9e5102b08b7bc509bcc63"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "89ff94ac1c577eced3afc9a81689d30ca238a8472ad0f025f6bed57a98dbb273"
		reason = "Quakbot"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Power Save Systems s.r.o." and pe.signatures[i].serial=="47:28:18:9f:a0:f5:77:93:48:4c:df:76:4f:5e:28:3d")
}
