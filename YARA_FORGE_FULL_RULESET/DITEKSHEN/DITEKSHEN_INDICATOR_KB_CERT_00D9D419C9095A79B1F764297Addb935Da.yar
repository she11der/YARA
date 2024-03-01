import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00D9D419C9095A79B1F764297Addb935Da : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "7c45a78c-2cde-5200-81fd-239effef7fe6"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L3997-L4008"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "dd35b48752eec01e1bfff182410da9a857735e0052e9c1a0d7c366dbee808d3c"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "7d45ec21c0d6fd0eb84e4271655eb0e005949614"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "OOO Nova soft" and pe.signatures[i].serial=="00:d9:d4:19:c9:09:5a:79:b1:f7:64:29:7a:dd:b9:35:da")
}
