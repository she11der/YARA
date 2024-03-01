import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_0097Df46Acb26B7C81A13Cc467B47688C8 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "1c281766-abd4-534b-9442-233369e1f55e"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L2222-L2233"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "ab4da0ddd001acf9f8d78c4beb28c648f8516088561e3140739b4b41d93b58ef"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "54c4929195fafddfd333871471a015fa68092f44e2f262f2bbf4ee980b41b809"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Information Civilized System Oy" and pe.signatures[i].serial=="00:97:df:46:ac:b2:6b:7c:81:a1:3c:c4:67:b4:76:88:c8")
}
