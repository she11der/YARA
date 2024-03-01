import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_7E0Ccda0Ef37Acef6C2Ebe4538627E5C : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "89006ac2-5cbc-5e7f-9ca6-51316b8d4bfd"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L81-L92"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "aed6c65f9c6400c0cc94386be684d3b9dd8d7637f9798fb49f4f651cf28b2d12"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "a758d6799e218dd66261dc5e2e21791cbcccd6cb"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Orangetree B.V." and pe.signatures[i].serial=="7e:0c:cd:a0:ef:37:ac:ef:6c:2e:be:45:38:62:7e:5c")
}
