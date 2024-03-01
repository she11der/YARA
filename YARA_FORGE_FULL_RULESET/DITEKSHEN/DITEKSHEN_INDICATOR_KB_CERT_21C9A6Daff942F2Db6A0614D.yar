import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_21C9A6Daff942F2Db6A0614D : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "e09476f7-d48d-58e5-aeca-fffacf569243"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L3256-L3267"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "c466a829d8141ba40187309559f62af73ea47e325eb95ef4c634bac60167788b"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "7dd9acb2ef0402883c65901ebbafd06e5293d391"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Ledger SAS" and pe.signatures[i].serial=="21:c9:a6:da:ff:94:2f:2d:b6:a0:61:4d")
}
