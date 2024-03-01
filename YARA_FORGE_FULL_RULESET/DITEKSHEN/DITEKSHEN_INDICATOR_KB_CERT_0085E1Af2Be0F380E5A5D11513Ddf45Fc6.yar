import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_0085E1Af2Be0F380E5A5D11513Ddf45Fc6 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "d55fd5ca-0e20-51de-84b6-f30dd2660529"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L2274-L2285"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "5a86b9aecf7697bd8e1f40407934c6a9941714404a931b0f1bed4ae7440f6921"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "e9849101535b47ff2a67e4897113c06f024d33f575baa5b426352f15116b98b4"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Makke Digital Works" and pe.signatures[i].serial=="00:85:e1:af:2b:e0:f3:80:e5:a5:d1:15:13:dd:f4:5f:c6")
}
