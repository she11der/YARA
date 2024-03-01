import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_Bd1E93D5787A737Eef930C70986D2A69 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "3b5ec355-9d68-5285-bda0-ddd379ad1cf8"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L3204-L3215"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "0332d05f0f53ad22516fd41cb10238ad0b92ef49011e9e71a82fa2da1de5e953"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "921e5d7f9f05272b566533393d7194ea9227e582"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Cdefedddbdedbcbfffbeadb" and pe.signatures[i].serial=="bd:1e:93:d5:78:7a:73:7e:ef:93:0c:70:98:6d:2a:69")
}
