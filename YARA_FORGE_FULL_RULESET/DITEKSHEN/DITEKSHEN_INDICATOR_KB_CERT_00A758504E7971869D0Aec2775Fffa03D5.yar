import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00A758504E7971869D0Aec2775Fffa03D5 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "1ecfe521-0148-5a13-b23f-dd1b14b835ed"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L6814-L6829"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "08f52e96d1e93e2d406753fd0dee5d03501ac037ab022b710362b113eaae6239"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "646bbb3a37cc004bea6efcd48579d1a5776cb157"
		hash1 = "3194e2fb68c007cf2f6deaa1fb07b2cc68292ee87f37dff70ba142377e2ca1fa"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Amcert LLC" and (pe.signatures[i].serial=="a7:58:50:4e:79:71:86:9d:0a:ec:27:75:ff:fa:03:d5" or pe.signatures[i].serial=="00:a7:58:50:4e:79:71:86:9d:0a:ec:27:75:ff:fa:03:d5"))
}
