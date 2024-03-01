import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_F64E5B34Dc0E4893495D3B9Fd9Cde4B7 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "d408b662-6328-55a8-ab64-42ea8f18c1cf"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L6525-L6536"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "497e63e4a19fa5b05d1098177dc73ae2255d4608d97e1001461dc4f8edced169"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "49373674eb2190c227455c9b5833825fe01f957a"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "AMASoft" and pe.signatures[i].serial=="f6:4e:5b:34:dc:0e:48:93:49:5d:3b:9f:d9:cd:e4:b7")
}
