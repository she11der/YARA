import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_282A8A04073Eced658B9770Bda8C0D28 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "d735ccfc-3f5e-5858-95ec-f385172ea8e6"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L8671-L8684"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "4cfebe55887a2a09293678e4dff2f93f22bec151dada7c84a41ac6deb10b7cc3"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "5cd4832101eb4f173c43986d5711087c8de25e6fcaef2f333e98a013e29b8373"
		reason = "RedLineStealer"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "OOO Betamaynd" and pe.signatures[i].serial=="28:2a:8a:04:07:3e:ce:d6:58:b9:77:0b:da:8c:0d:28")
}
