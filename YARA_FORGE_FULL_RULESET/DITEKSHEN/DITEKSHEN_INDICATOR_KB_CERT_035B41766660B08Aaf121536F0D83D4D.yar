import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_035B41766660B08Aaf121536F0D83D4D : FILE
{
	meta:
		description = "Detects signed excutable of DiskCryptor open encryption solution that offers encryption of all disk partitions"
		author = "ditekSHen"
		id = "80c803e1-16b8-583d-9d4f-3a0f693c9e24"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L7295-L7306"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "924ed1d3c6a8d378471a2e5301f3a813ee8622135ce001d3061918d9454cdcc4"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "2022d012c23840314f5eeaa298216bec06035787"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Alexander Lomachevsky" and pe.signatures[i].serial=="03:5b:41:76:66:60:b0:8a:af:12:15:36:f0:d8:3d:4d")
}
