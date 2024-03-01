import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_0940Fa9A4080F35052B2077333769C2F : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "2cc722de-97ff-53d1-9436-dc88c844186b"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L3906-L3917"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "3ecf6982c779a5fd867fef4b753313e379151491fa8865e8ae20f0c9362431a2"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "da154c058cd75ff478b248701799ea8c683dd7a5"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "PROFF LAIN, OOO" and pe.signatures[i].serial=="09:40:fa:9a:40:80:f3:50:52:b2:07:73:33:76:9c:2f")
}
