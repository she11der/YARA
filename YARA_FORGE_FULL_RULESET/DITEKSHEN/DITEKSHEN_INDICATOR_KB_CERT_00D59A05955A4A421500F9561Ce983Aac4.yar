import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00D59A05955A4A421500F9561Ce983Aac4 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "97c4e8fa-8d66-500f-a63f-fac84ad9e508"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L2313-L2324"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "9187dcdbf29e5119d90ede266a14c7e46f5050800a38c57fa86e957c885c1d60"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "7f56555ac8479d4e130a89e787b7ff2f47005cc02776cf7a30a58611748c4c2e"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Olymp LLC" and pe.signatures[i].serial=="00:d5:9a:05:95:5a:4a:42:15:00:f9:56:1c:e9:83:aa:c4")
}
