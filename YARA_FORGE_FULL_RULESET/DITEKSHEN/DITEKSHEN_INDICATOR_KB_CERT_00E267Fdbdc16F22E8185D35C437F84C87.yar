import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00E267Fdbdc16F22E8185D35C437F84C87 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "520e335d-4b9f-5006-959a-1510312807be"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L3137-L3148"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "403f0f8a65997d27494d7ac4aa99cf5ebb1471839f67b2f8b380225a0263fd67"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "cdf4a69402936ece82f3f9163e6cc648bcbb2680"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "APOTHEKA, s.r.o." and pe.signatures[i].serial=="00:e2:67:fd:bd:c1:6f:22:e8:18:5d:35:c4:37:f8:4c:87")
}
