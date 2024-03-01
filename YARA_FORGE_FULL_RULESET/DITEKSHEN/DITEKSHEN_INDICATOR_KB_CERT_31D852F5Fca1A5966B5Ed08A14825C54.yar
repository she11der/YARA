import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_31D852F5Fca1A5966B5Ed08A14825C54 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "8d65caa2-ce28-5f9b-b8a5-3fe903dd5628"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L5020-L5031"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "e2890f8c623ce15d8a3f996e87be4b73a8cd9f96386ce8d356d7e0fad0342dd3"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "a657b8f2efea32e6a1d46894764b7a4f82ad0b56"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "BBT KLA d.o.o." and pe.signatures[i].serial=="31:d8:52:f5:fc:a1:a5:96:6b:5e:d0:8a:14:82:5c:54")
}
