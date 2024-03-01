import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_2Dcd0699Da08915Dde6D044Cb474157C : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "0b4e1d10-d385-5ca8-b9e2-00341a4c6fd9"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L2495-L2506"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "096cf4bb17aa86821bd8d6c8b9fd603664beb12f54a97a87e660b560bd0fc246"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "13bf3156e66a57d413455973866102b0a1f6d45a1e6de050ca9dcf16ecafb4e2"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "VENTE DE TOUT" and pe.signatures[i].serial=="2d:cd:06:99:da:08:91:5d:de:6d:04:4c:b4:74:15:7c")
}
