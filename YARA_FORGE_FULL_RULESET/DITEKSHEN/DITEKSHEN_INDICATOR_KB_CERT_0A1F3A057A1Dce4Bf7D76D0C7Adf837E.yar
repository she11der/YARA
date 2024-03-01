import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_0A1F3A057A1Dce4Bf7D76D0C7Adf837E : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "c4829ec0-b6be-5701-a4cf-e4b1205240b3"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L6172-L6184"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		hash = "2df05a70d3ce646285a0f888df15064b4e73034b67e06d9a4f4da680ed62e926"
		logic_hash = "de9ae66e497730db54fc21a745426c687c3a4d9819c08bc1dca0b42a5b8070ac"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "8279b87c89507bc6e209a7bd8b5c24b31fb9a6dc"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Beijing Qihu Technology Co., Ltd." and pe.signatures[i].serial=="0a:1f:3a:05:7a:1d:ce:4b:f7:d7:6d:0c:7a:df:83:7e")
}
