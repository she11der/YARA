import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00Cc95D6Ebf18A3711E196Aea210465A19 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "bd6957ac-d5e0-5e77-87b3-a62c442f7f72"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L5406-L5417"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "640ba6d64ad7e0791ef29d3ee9387e0944826f22f01a6a01486f6b3ac4138826"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "319f0e03f0f230629258c7ea05e7d56ead830ce9"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "GEN Sistemi, d.o.o." and pe.signatures[i].serial=="00:cc:95:d6:eb:f1:8a:37:11:e1:96:ae:a2:10:46:5a:19")
}
