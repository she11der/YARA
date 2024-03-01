import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_767436921B2698Bd18400A24B01341B6 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "ffd19457-1a5d-5782-89e2-3dd4090f124f"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L902-L913"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "b09ec625a06dcf90df52c56b78889f24d55dbd8cbd7d82a07bdbc842318ff19a"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "871899843b5fd100466e351ca773dac44e936939"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "REBROSE LEISURE LIMITED" and pe.signatures[i].serial=="76:74:36:92:1b:26:98:bd:18:40:0a:24:b0:13:41:b6")
}
