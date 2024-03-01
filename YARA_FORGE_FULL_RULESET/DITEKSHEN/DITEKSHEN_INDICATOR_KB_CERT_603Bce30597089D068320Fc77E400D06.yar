import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_603Bce30597089D068320Fc77E400D06 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "0f2a2411-f3d4-5959-8470-d7424d714c1d"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L3412-L3423"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "1e13c78cec21a015d9593b492ce5040f93247be63c079bfece96a3a74055aeba"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "4ddda7e006afb108417627f8f22a6fa416e3f264"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Fcaddefffedacfc" and pe.signatures[i].serial=="60:3b:ce:30:59:70:89:d0:68:32:0f:c7:7e:40:0d:06")
}
