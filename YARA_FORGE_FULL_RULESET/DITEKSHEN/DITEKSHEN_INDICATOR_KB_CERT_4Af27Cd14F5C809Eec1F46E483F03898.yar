import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_4Af27Cd14F5C809Eec1F46E483F03898 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "e7bbc10b-54fc-5950-99fc-80a459406780"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L2651-L2662"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "0297f156d1e4d1c20143953759000b286ac9e1f8864aa511e0e2f8fa5c3eac7f"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "5fa9a98f003f2680718cbe3a7a3d57d7ba347ecb"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "DAhan Advertising planning" and pe.signatures[i].serial=="4a:f2:7c:d1:4f:5c:80:9e:ec:1f:46:e4:83:f0:38:98")
}
