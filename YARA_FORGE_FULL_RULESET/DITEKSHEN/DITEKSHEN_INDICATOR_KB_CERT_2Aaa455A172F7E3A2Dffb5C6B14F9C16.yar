import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_2Aaa455A172F7E3A2Dffb5C6B14F9C16 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "81c115a7-7ddf-58ba-b56e-a92652c7f217"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L7487-L7499"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "dd10d388e9122585c8e5b2073725f50edbc85d0ca1e94a4b034e500e0e89b608"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "23c91b66bd07e56e60724b0064d4fedbdb1c8913"
		hash1 = "7852cf2dfe60b60194dae9b037298ed0a9c84fa1d850f3898751575f4377215f"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "DREAM VILLAGE s.r.o." and pe.signatures[i].serial=="2a:aa:45:5a:17:2f:7e:3a:2d:ff:b5:c6:b1:4f:9c:16")
}
