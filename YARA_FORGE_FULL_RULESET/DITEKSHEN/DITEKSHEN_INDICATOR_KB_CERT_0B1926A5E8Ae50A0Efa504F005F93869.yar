import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_0B1926A5E8Ae50A0Efa504F005F93869 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "905a4b5c-3255-5f53-be54-429038378ee0"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L393-L404"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "78d507f76d44ed982d12c293604d5c4fed14316cbc18473b7131bb89997bad28"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "2052ed19dcb0e3dfff71d217be27fc5a11c0f0d4"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Nordkod LLC" and pe.signatures[i].serial=="0b:19:26:a5:e8:ae:50:a0:ef:a5:04:f0:05:f9:38:69")
}
