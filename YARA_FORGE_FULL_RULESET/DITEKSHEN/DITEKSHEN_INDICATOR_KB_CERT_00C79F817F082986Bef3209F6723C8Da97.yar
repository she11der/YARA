import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00C79F817F082986Bef3209F6723C8Da97 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "2e831cd7-6992-5b5f-ad84-52590f3cc65a"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L5843-L5856"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "b6dd9cb0d2383bce3ab13b6a660b3f5ba554a2bf1fce4aabb6dd36187cc57f45"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "e2bf86dc46fca1c35f98ff84d8976be8aa0668bc"
		hash1 = "dd49651e325b04ea14733bcd676c0a1cb58ab36bf79162868ade02b396ec3ab0"
		hash2 = "823cb4b92a1266c880d917c7d6f71da37d524166287b30c0c89b6bb03c2e4b64"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Al-Faris group d.o.o." and pe.signatures[i].serial=="00:c7:9f:81:7f:08:29:86:be:f3:20:9f:67:23:c8:da:97")
}
