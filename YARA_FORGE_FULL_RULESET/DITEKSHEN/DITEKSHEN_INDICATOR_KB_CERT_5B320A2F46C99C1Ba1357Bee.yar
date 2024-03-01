import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_5B320A2F46C99C1Ba1357Bee : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "376aab03-0bc7-5993-bbbd-9bf5b742d29d"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L445-L456"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "b0a515aa69b5de58cf7d1a496f95038e090cefe511803e7a29332b411a20d19f"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "5ae8bd51ffa8e82f8f3d8297c4f9caf5e30f425a"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "REGION TOURISM LLC" and pe.signatures[i].serial=="5b:32:0a:2f:46:c9:9c:1b:a1:35:7b:ee")
}
