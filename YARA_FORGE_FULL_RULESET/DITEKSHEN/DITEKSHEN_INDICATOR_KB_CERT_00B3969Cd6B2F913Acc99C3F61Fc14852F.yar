import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00B3969Cd6B2F913Acc99C3F61Fc14852F : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "2cd4cee3-0adc-595f-b86f-7c515cd0ea64"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L4604-L4619"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "4ee7f3da2ae707517c1c426e6a73fdede51514e4ddf60b93fd77c1b6c23e82c0"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "bd9cadcfb5cde90f493a92e43f49bf99db177724"
		hash1 = "a4d9cf67d111b79da9cb4b366400fc3ba1d5f41f71d48ca9c8bb101cb4596327"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "S.O.M GmbH" and (pe.signatures[i].serial=="b3:96:9c:d6:b2:f9:13:ac:c9:9c:3f:61:fc:14:85:2f" or pe.signatures[i].serial=="00:b3:96:9c:d6:b2:f9:13:ac:c9:9c:3f:61:fc:14:85:2f"))
}
