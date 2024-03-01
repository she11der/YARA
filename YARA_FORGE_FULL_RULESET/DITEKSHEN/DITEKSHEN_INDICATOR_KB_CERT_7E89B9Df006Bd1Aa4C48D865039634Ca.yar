import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_7E89B9Df006Bd1Aa4C48D865039634Ca : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "aa208da9-06e2-5bf5-8453-a545c640efa7"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L2690-L2701"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "825e4b69aec565b6ef6b4ac2394f5a562a84615e3c91331934fa378152635df4"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "63ad44acaa7cd7f8249423673fbf3c3273e7b2dc"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Dummy" and pe.signatures[i].serial=="7e:89:b9:df:00:6b:d1:aa:4c:48:d8:65:03:96:34:ca")
}
