import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_630Cf0E612F12805Ffa00A41D1032D7C : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "1c3e2b33-24e5-584c-b375-96c1e653a3ca"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L3399-L3410"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "2256858ae75c47568fc6a38e2a587d302d99dd396dd398a450eaa6459ed55d13"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "107af72db66ec4005ed432e4150a0b6f5a9daf2d"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Dadebfaca" and pe.signatures[i].serial=="63:0c:f0:e6:12:f1:28:05:ff:a0:0a:41:d1:03:2d:7c")
}
