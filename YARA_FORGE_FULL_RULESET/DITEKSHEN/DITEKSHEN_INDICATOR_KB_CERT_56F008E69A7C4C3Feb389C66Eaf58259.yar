import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_56F008E69A7C4C3Feb389C66Eaf58259 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "bcd0cd8e-82ec-5d20-85d1-cbad455b6d90"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L4830-L4841"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "3ba02eb734b461b02744c5fc901e45f4574249607398fb8a73850d5d5e89788b"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "a7dc8cb973ef5f54af0889549d84dee51a7db839"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "MEDIATEK INC." and pe.signatures[i].serial=="56:f0:08:e6:9a:7c:4c:3f:eb:38:9c:66:ea:f5:82:59")
}
