import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00Ac307E5257Bb814B818D3633B630326F : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "b6d6c195-cd02-5ecd-82f3-348ab6f26eb5"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L2809-L2820"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "f187d3084eb189cdd0e858aed1d9589d586f369b128679c6c1dec860e544f326"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "4d6a089ec4edcac438717c1d64a8be4ef925a9c6"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Aqua Direct s.r.o." and pe.signatures[i].serial=="00:ac:30:7e:52:57:bb:81:4b:81:8d:36:33:b6:30:32:6f")
}
