import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00Ced72Cc75Aa0Ebce09Dc0283076Ce9B1 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "7482c8a9-22d7-5ecf-951c-83818e2aeda7"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L3056-L3067"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "47fceb2a79271011bc6feed209ef4021db155dbc0fd4891f0dc1e900f2cb7fdb"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "db77b48a7f16fecd49029b65f122fa0782b4318f"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Valerie LLC" and pe.signatures[i].serial=="00:ce:d7:2c:c7:5a:a0:eb:ce:09:dc:02:83:07:6c:e9:b1")
}
