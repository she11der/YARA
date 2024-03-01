import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_387Eeb89B8Bf626Bbf4C7C9F5B998B40 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "56dfc1b5-3aba-5c21-93e6-85d41a2a4415"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L7281-L7293"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "3436b7954e5488614f8f0998fe9eae7773d821c776436836d7b2230cd9c97f46"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "e94ad249747fd4b88750b2cd6d8d65ad33d3566d"
		hash1 = "004f011b37e4446fa04b76aae537cc00f6588c0705839152ae2d8a837ef2b730"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ULTRA ACADEMY LTD" and pe.signatures[i].serial=="38:7e:eb:89:b8:bf:62:6b:bf:4c:7c:9f:5b:99:8b:40")
}
