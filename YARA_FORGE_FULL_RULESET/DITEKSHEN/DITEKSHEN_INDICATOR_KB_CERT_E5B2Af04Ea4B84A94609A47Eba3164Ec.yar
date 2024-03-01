import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_E5B2Af04Ea4B84A94609A47Eba3164Ec : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "ea78ae13-cd9f-578a-95e4-906ab7045faf"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L4660-L4671"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "2e32bb0d9689625cd860a75539961410241de341ad4b7ee661df7d3b2dd47c46"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "7785d50066faee71d1a463584c1a97f34431ddfe"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "RRGRQJRWZHRTLFAUVK" and pe.signatures[i].serial=="e5:b2:af:04:ea:4b:84:a9:46:09:a4:7e:ba:31:64:ec")
}
