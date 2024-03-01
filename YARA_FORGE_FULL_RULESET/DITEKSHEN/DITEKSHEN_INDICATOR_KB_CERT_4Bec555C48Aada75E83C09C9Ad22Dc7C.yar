import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_4Bec555C48Aada75E83C09C9Ad22Dc7C : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "664b8f55-03f8-5f36-aaf7-60ee4e613af4"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L1192-L1203"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "de4562f70bbe25aa053f2476efca12b99cd4f2ee721df620d02d004bac2a59f9"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "a2be2ab16e3020ddbff1ff37dbfe2d736be7a0d5"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "\\xD0\\x92\\xE5\\xB1\\x81\\xE5\\xB0\\x94\\xE5\\x90\\xBE\\xD0\\x92\\xE5\\x90\\x89\\xE5\\xB0\\x94\\xE5\\x90\\xBE\\xD0\\x92\\xE4\\xB8\\x9D\\xE5\\xB1\\x81" and pe.signatures[i].serial=="4b:ec:55:5c:48:aa:da:75:e8:3c:09:c9:ad:22:dc:7c")
}
