import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_4Cdffb4F02C55Ae60A099652605Da274 : FILE
{
	meta:
		description = "Enigma Protector Demo Certificate"
		author = "ditekSHen"
		id = "843929be-68e5-56b0-99fc-f5d71b91c3cf"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L6366-L6377"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "1b655f42302bed2091aaa5d37156c68eaf812f0c287bf42b24942a8b845b7476"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "4a2d33148aadf947775a15f50535842633cc3442"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "DEMO" and pe.signatures[i].serial=="4c:df:fb:4f:02:c5:5a:e6:0a:09:96:52:60:5d:a2:74")
}
