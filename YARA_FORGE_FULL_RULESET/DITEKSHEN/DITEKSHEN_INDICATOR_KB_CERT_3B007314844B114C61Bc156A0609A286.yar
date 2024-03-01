import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_3B007314844B114C61Bc156A0609A286 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "bb68c2fc-2389-5fb8-96f0-5731f008fd3c"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L5682-L5693"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "f6f4e551a9be96f43a81e4da69f7b312dbdc16da17659a00a3486543a9c078e9"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "52ae9fdda7416553ab696388b66f645e07e753cd"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SATURDAY CITY LIMITED" and pe.signatures[i].serial=="3b:00:73:14:84:4b:11:4c:61:bc:15:6a:06:09:a2:86")
}
