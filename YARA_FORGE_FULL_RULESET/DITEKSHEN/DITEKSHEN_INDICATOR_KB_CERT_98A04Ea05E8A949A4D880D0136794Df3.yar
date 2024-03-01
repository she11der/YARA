import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_98A04Ea05E8A949A4D880D0136794Df3 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "cda10dcf-bc46-56d9-a4b5-60a76249334c"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L4335-L4346"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "05c63386558b954da3cfec1fd514a7a567189d9ac33d818cbbabf3eaf72ed130"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "0387ce856978cfa3e161fc03751820f003b478f3"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "FRVFMPRLNIMAMSUIMT" and pe.signatures[i].serial=="98:a0:4e:a0:5e:8a:94:9a:4d:88:0d:01:36:79:4d:f3")
}
