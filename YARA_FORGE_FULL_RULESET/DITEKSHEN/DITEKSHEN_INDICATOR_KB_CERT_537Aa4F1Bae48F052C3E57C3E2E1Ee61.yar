import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_537Aa4F1Bae48F052C3E57C3E2E1Ee61 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "33316c5e-b14f-50b5-8971-3a8b5a3c2497"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L5975-L5986"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "83d205998f43a2404146064e13726c149bc56fed6b886ee1812378c027f03da0"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "15355505a242c44d6c36abab6267cc99219a931c"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ALPHA AME LIMITED LLP" and pe.signatures[i].serial=="53:7a:a4:f1:ba:e4:8f:05:2c:3e:57:c3:e2:e1:ee:61")
}
