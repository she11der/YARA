import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_008Cff807Edaf368A60E4106906D8Df319 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "ad8bed7f-3bc6-53d3-9e7a-0868e2ad267a"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L1689-L1700"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "48752aff88cd3d546757a4220a64ca17cc9a5f00a42d2bc0571dedf5de769bc2"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "c97d809c73f376cdf8062329b357b16c9da9d14261895cd52400f845a2d6bdb1"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "KRAFT BOKS OOO" and pe.signatures[i].serial=="00:8c:ff:80:7e:da:f3:68:a6:0e:41:06:90:6d:8d:f3:19")
}
