import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_1E508Bb2398808Bc420A5A1F67Ba5D0B : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "32f79595-6526-5dea-824a-cc073b6a2b5c"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L6728-L6740"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "71b7efab5359408e3897498ce031c8375e2d67bfc8ff15c685df5ac6dd4bb015"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "63a3ca4114aef8d5076ec84ff78d2319d5305e5b"
		hash1 = "7ff82a6621e0dd7c29c2e6bcd63920f9b58bc254df9479618b912a1e788ff18b"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "WakeNet AB" and pe.signatures[i].serial=="1e:50:8b:b2:39:88:08:bc:42:0a:5a:1f:67:ba:5d:0b")
}
