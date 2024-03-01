import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_085B70224253486624Fc36Fa658A1E32 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "8d0f4499-1ed2-5277-be80-0b7f3499b360"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L224-L235"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "8779cca652b366ce33a3735069fdc35657a6bed5b469a956cd236d76901f8f54"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "36834eaf0061cc4b89a13e019eccc6e598657922"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Best Fud, OOO" and pe.signatures[i].serial=="08:5b:70:22:42:53:48:66:24:fc:36:fa:65:8a:1e:32")
}
