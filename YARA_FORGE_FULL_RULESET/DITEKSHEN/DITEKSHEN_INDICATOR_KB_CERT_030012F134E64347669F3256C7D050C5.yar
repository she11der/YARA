import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_030012F134E64347669F3256C7D050C5 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "7f16b535-8a0f-583d-8bc3-0abf24f26632"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L159-L170"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "68bfd2e146e3b2bd1222de7f9981bb0e373bcb4727a81eb7060af36e6275d438"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "959caa354b28892608ab1bb9519424c30bebc155"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Futumarket LLC" and pe.signatures[i].serial=="03:00:12:f1:34:e6:43:47:66:9f:32:56:c7:d0:50:c5")
}
