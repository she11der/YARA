import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_6E3B09F43C3A0Fd53B7D600F08Fae2B5 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "d23e7b9b-4424-50c5-a768-9cb33e0de192"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L4244-L4255"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "45e2833dedacd875912d07dc63216400ddff76846f9c7bdf808f1db56ed4720c"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "677054afcbfecb313f93f27ed159055dc1559ad0"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Divisible Limited" and pe.signatures[i].serial=="6e:3b:09:f4:3c:3a:0f:d5:3b:7d:60:0f:08:fa:e2:b5")
}
