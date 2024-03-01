import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00989A33B72A2Aa29E32D0A5E155C53963 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "59fcdc74-ca44-5d30-b9b0-5e9c7a3b50f3"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L6668-L6682"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "f016093cd512bcbf31814ff1619441e476b3988d0670f469f6311eda37ae295d"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "3f53d410d2d959197f4a93d81a898f424941e11f"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "TAKE CARE SP Z O O" and (pe.signatures[i].serial=="98:9a:33:b7:2a:2a:a2:9e:32:d0:a5:e1:55:c5:39:63" or pe.signatures[i].serial=="00:98:9a:33:b7:2a:2a:a2:9e:32:d0:a5:e1:55:c5:39:63"))
}
