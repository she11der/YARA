import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_8Cece6Df54Cf6Ad63596546D77Ba3581 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "c5c19072-5a2f-5851-83bf-25a9e2fd9033"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L8761-L8774"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "1980b3ef7df1bfa43d401fdd8393cb8ffb5c919d558c23314ffb9e823cf9590d"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "1a9ff8aba1b24e3bd06442ac6d593ff224b685cba4edef79e740f569ab453161"
		reason = "Malware"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Mikael LLC" and pe.signatures[i].serial=="8c:ec:e6:df:54:cf:6a:d6:35:96:54:6d:77:ba:35:81")
}
