import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_7Ed801843Fa001B8Add52D3A97B25931 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "8dc9fbde-57bb-56ca-b925-902059612606"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L5949-L5960"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "2607dde1318b9b84056fc73664e4c1f82f20c23f311216e2201c3fdee0d1b6db"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "4ee1539c1455f0070d8d04820fb814f8794f84df"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "AM El-Teknik ApS" and pe.signatures[i].serial=="7e:d8:01:84:3f:a0:01:b8:ad:d5:2d:3a:97:b2:59:31")
}
