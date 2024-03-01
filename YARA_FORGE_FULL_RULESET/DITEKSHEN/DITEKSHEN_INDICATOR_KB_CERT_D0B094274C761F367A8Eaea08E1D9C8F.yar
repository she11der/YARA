import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_D0B094274C761F367A8Eaea08E1D9C8F : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "3683b66b-3dc0-5b89-be71-1e1267ef7de8"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L2300-L2311"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "5ce9be0bdd8350dd5a8ae8cf2447d1be6b34ee3abc5c19754c63ef03b7cccec9"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "e94a9d81c4a67ef953fdb27aad6ec8fa347e6903b140d21468066bdca8925bc5"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Nsasoft US LLC" and pe.signatures[i].serial=="d0:b0:94:27:4c:76:1f:36:7a:8e:ae:a0:8e:1d:9c:8f")
}
