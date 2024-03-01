import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_F90E68Cbf92Fd7Ad409E281C3F2A0F0A : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "e92daa7b-2d8a-5806-840e-678a9aa24fef"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L5125-L5137"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		hash = "d79a8f491c0112c3f26572350336fe7d22674f5550f37894643eba980ae5bd32"
		logic_hash = "ca8d80a446df0c28e9fb4944bd69d9fa008be968c449e5a469b182fbf8744a3f"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "c202564339ddd78a1ce629ce54824ba2697fa3d6"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SUCK-MY-DICK-ESET" and pe.signatures[i].serial=="f9:0e:68:cb:f9:2f:d7:ad:40:9e:28:1c:3f:2a:0f:0a")
}
