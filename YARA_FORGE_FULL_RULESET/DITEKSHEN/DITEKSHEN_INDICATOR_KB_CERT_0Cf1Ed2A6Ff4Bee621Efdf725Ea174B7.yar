import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_0Cf1Ed2A6Ff4Bee621Efdf725Ea174B7 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "f3cb7bd9-9e28-5478-b65d-60915157dd3b"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L5936-L5947"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "2902b075f40f1413eee937c045e082a3141ec309f9d8e1dfd3a384050ea0776c"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "e33dc0787099d92a712894cfef2aaba3f0d65359"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "LEVEL LIST SP Z O O" and pe.signatures[i].serial=="0c:f1:ed:2a:6f:f4:be:e6:21:ef:df:72:5e:a1:74:b7")
}
