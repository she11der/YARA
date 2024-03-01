import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_29A248A77D5D4066Fe5Da75F32102Bb5 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "b71f4ee4-55d1-51c7-8fc3-1c6fcaa64a86"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L928-L939"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "063a8b361e9fc91619912109427f6a0cbc7755e85dae820ea0f16709ac580ed1"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "1078c0ab5766a48b0d4e04e57f3ab65b68dd797f"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SUN & STARZ LIMITED" and pe.signatures[i].serial=="29:a2:48:a7:7d:5d:40:66:fe:5d:a7:5f:32:10:2b:b5")
}
