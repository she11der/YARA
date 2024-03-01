import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_01Ea62E443Cb2250C870Ff6Bb13Ba98E : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "40c5f73b-70b6-5db7-8060-01ad77e5f319"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L4088-L4099"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "dbf281989fb89976f83e0e2395f02c1e8c4c9ec5f96095786d9c6406518eb315"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "f293eed3ff3d548262cddc43dce58cfc7f763622"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Tencent Technology(Shenzhen) Company Limited" and pe.signatures[i].serial=="01:ea:62:e4:43:cb:22:50:c8:70:ff:6b:b1:3b:a9:8e")
}
