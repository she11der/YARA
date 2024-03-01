import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_1C7D3F6E116554809F49Ce16Ccb62E84 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "66f4c531-5c0d-5467-a875-eff00a5d00c8"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L601-L612"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "f24037e6ac40844095e06ea12cebdf4dd22a35382c728f9586b90e40c57a4188"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = ""
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "1549 LIMITED" and pe.signatures[i].serial=="1c:7d:3f:6e:11:65:54:80:9f:49:ce:16:cc:b6:2e:84")
}
