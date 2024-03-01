import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_0Ddce8Cdc91B5B649Bb4B45Ffbba6C6C : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "180b2e63-7151-5899-8c12-7e4cd3bb2e0d"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L2638-L2649"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "940d257253a0a1a3f70dcec1cb57e9ab08108138ce3b80c9f74228a8b702601c"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "23c446940a9cdc9f502b92d7928e3b3fde6d3735"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SLIM DOG GROUP SP Z O O" and pe.signatures[i].serial=="0d:dc:e8:cd:c9:1b:5b:64:9b:b4:b4:5f:fb:ba:6c:6c")
}
