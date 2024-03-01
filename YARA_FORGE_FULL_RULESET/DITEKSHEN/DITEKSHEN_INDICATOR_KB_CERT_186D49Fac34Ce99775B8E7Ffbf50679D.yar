import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_186D49Fac34Ce99775B8E7Ffbf50679D : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "eeea3085-9fd7-5077-8c13-e0c4438b2e79"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L2209-L2220"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "950b14787e707be843d1443a612c372ceb0c2830de20bce1f62317fa39149e5b"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "812a80556775d658450362e1b3650872b91deba44fef28f17c9364add5aa398e"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Hairis LLC" and pe.signatures[i].serial=="18:6d:49:fa:c3:4c:e9:97:75:b8:e7:ff:bf:50:67:9d")
}
