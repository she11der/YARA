import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_0F7E3Fda780E47E171864D8F5386Bc05 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "33b8ce54-fa2c-5aac-9022-2309f7fc4a86"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L4192-L4203"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "30e2daf85ee7f9f9615a49af949a034b50a97a1a7abf6a318547809cc9e7b0b7"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "1e3dd5576fc57fa2dd778221a60bd33f97087f74"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Louhos Solutions Oy" and pe.signatures[i].serial=="0f:7e:3f:da:78:0e:47:e1:71:86:4d:8f:53:86:bc:05")
}
