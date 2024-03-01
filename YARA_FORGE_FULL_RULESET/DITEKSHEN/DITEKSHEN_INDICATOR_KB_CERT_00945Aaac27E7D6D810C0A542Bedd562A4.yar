import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00945Aaac27E7D6D810C0A542Bedd562A4 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "5698130c-0696-5474-8b86-b6ba290d2822"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L6957-L6972"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "292657717cb42835324b6ff42d563bca47e042e82afef24b5d666b16979b8103"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "de7794505df4aeb1253500617e812f462592e163"
		hash1 = "df3dabd031184b67bab7043baaae17061c21939d725e751c0a6f6b7867d0cf34"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "DYNAMX BUSINESS GROUP LTD." and (pe.signatures[i].serial=="94:5a:aa:c2:7e:7d:6d:81:0c:0a:54:2b:ed:d5:62:a4" or pe.signatures[i].serial=="00:94:5a:aa:c2:7e:7d:6d:81:0c:0a:54:2b:ed:d5:62:a4"))
}
