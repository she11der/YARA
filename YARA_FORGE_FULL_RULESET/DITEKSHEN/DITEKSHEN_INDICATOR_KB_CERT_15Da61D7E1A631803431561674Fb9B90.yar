import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_15Da61D7E1A631803431561674Fb9B90 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "d1fd8200-0960-567d-9bb6-2bd1ed99f61b"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L4483-L4494"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "4d30a4bf1b0425081369351df707be0531dcc1751512d9012a859b621d61a1b3"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "9a9bc3974e3cbbabdeb2b6debdc0455586e128a4"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "JAY DANCE STUDIO d.o.o." and pe.signatures[i].serial=="15:da:61:d7:e1:a6:31:80:34:31:56:16:74:fb:9b:90")
}
