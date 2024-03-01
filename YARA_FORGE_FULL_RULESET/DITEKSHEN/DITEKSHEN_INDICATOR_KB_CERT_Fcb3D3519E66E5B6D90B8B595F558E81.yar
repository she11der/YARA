import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_Fcb3D3519E66E5B6D90B8B595F558E81 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "966650b5-d776-5ed0-a99b-507b46abd882"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L2365-L2376"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "62c7189cc906b9f2d2724492489218d9aecf08ef431463ebf1963b034222f2ad"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "8bf6e51dfe209a2ca87da4c6b61d1e9a92e336e1a83372d7a568132af3ad0196"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Pegasun" and pe.signatures[i].serial=="fc:b3:d3:51:9e:66:e5:b6:d9:0b:8b:59:5f:55:8e:81")
}
