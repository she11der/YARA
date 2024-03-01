import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_294E7A2Ccfc28Ed02843Ecff25F2Ac98 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "ae3c0758-7863-54eb-a94f-3c86d5d34d21"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L3230-L3241"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "75c3093978875c7e523525a3b64bf985139359d9696fdb9dbd7db3e915043194"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "a57a2de9b04a80e9290df865c0abd3b467318144"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Eadbaadbdcecafdfafbe" and pe.signatures[i].serial=="29:4e:7a:2c:cf:c2:8e:d0:28:43:ec:ff:25:f2:ac:98")
}
