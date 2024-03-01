import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00B61B8E71514059Adc604Da05C283E514 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "d52bd370-a1da-56f1-8edd-da61c9e2e75b"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L133-L144"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "b771d40e4e2db1d3f26d8fb2fa140f57871712700e584005d2377b701fc9538a"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "67ee69f380ca62b28cecfbef406970ddd26cd9be"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "APP DIVISION ApS" and pe.signatures[i].serial=="00:b6:1b:8e:71:51:40:59:ad:c6:04:da:05:c2:83:e5:14")
}
