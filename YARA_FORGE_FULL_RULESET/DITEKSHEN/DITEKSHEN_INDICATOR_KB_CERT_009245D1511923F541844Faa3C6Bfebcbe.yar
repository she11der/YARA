import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_009245D1511923F541844Faa3C6Bfebcbe : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "db876459-a0d2-542f-8f7e-a486ba68aeb4"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L3776-L3787"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "8d2c186b3aaaf353857e67ffd51a785e674335e824be78fc1c2ae1b9a0532eae"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "509cbd2cd38ae03461745c7d37f6bbe44c6782cf"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "LEHTEH d.o.o.," and pe.signatures[i].serial=="00:92:45:d1:51:19:23:f5:41:84:4f:aa:3c:6b:fe:bc:be")
}
