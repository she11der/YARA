import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_1Aec3D3F752A38617C1D7A677D0B5591 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "8e1bb307-733c-5626-98f6-a5c2587bf800"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L4647-L4658"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "4bbe5aac8a470061abab48070fafd2100c577cab1f40fcc5924dbd13bc747487"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "1d41b9f7714f221d76592e403d2fbb0f0310e697"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SILVER d.o.o." and pe.signatures[i].serial=="1a:ec:3d:3f:75:2a:38:61:7c:1d:7a:67:7d:0b:55:91")
}
