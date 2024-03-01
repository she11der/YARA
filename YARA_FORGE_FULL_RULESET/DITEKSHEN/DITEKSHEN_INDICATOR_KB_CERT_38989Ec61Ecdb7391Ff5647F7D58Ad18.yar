import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_38989Ec61Ecdb7391Ff5647F7D58Ad18 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "40c742ec-f683-57fe-bb35-7c44617f9199"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L4981-L4992"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "f2108c41c814a815047268d9934a01231936a1cf73cbb92476eb96c9fe4b1091"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "71e74a735c72d220aa45e9f1b83f0b867f2da166"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "RotA Games ApS" and pe.signatures[i].serial=="38:98:9e:c6:1e:cd:b7:39:1f:f5:64:7f:7d:58:ad:18")
}
