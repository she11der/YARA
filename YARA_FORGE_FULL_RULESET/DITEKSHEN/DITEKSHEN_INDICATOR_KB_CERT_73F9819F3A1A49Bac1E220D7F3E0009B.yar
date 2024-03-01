import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_73F9819F3A1A49Bac1E220D7F3E0009B : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "06f448cf-1f0e-5db5-bdb5-30238c5f7341"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L954-L965"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "9244fae0be6c1addbd0c740d7e153fd4109101184bc61375ddadb6d784769010"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "bb04986cbd65f0994a544f197fbb26abf91228d9"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Jean Binquet" and pe.signatures[i].serial=="73:f9:81:9f:3a:1a:49:ba:c1:e2:20:d7:f3:e0:00:9b")
}
