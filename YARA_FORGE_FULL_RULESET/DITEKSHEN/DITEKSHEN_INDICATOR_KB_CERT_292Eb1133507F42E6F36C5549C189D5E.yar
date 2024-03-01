import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_292Eb1133507F42E6F36C5549C189D5E : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "60d3cc6e-bf58-55ae-a13b-0e22ecc8d5cd"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L7473-L7485"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "456a09b1939d3f60e6ef735631eb681a9d15ea573552672fd14b19f60e8d8c73"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "48c32548ff651e2aac12716efb448f5583577e35"
		hash1 = "f0b3b36086e58964bf4b9d655568ab5c7f798bd89e7a8581069e65f8189c0b79"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Affairs-case s.r.o." and pe.signatures[i].serial=="29:2e:b1:13:35:07:f4:2e:6f:36:c5:54:9c:18:9d:5e")
}
