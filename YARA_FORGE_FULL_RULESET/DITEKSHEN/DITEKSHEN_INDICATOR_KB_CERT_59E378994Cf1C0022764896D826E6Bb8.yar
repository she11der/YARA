import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_59E378994Cf1C0022764896D826E6Bb8 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "465d0b0c-c9fa-5364-a5f4-0d765ee40081"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L640-L651"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "1720636723f0eeab074e29e7c9bf2df3c8d951e27b25ea4b7db60f6c00102589"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "9a17d31e9191644945e920bc1e7e08fbd00b62f4"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SEVA MEDICAL LTD" and pe.signatures[i].serial=="59:e3:78:99:4c:f1:c0:02:27:64:89:6d:82:6e:6b:b8")
}
