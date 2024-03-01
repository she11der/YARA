import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_635517466B67Bd4Bba805Bc67Ac3328C : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "b7533186-b5dc-53ce-912b-39bd42c92071"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L4702-L4713"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "71cdb314e2f6bda70f9f627d72aea49290fdbce66f76a170aa6571873ca82860"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "0b3144ec936028cbf5292504ef2a75eea8eb6c1d"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "MEDIATEK INC." and pe.signatures[i].serial=="63:55:17:46:6b:67:bd:4b:ba:80:5b:c6:7a:c3:32:8c")
}
