import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_008385684419Ab26A3F2640B1496E1Fe94 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "5aa92ac6-241f-54a1-b828-f8a5deb6d212"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L4634-L4645"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "7c9de438d5c7156052e30ce70310aaa989ff1896f7b34ffc6c4fd8fc2bc60b85"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "ee1d7d90957f3f2ccfcc069f5615a5bafdac322f"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "CAUSE FOR CHANGE LTD" and pe.signatures[i].serial=="00:83:85:68:44:19:ab:26:a3:f2:64:0b:14:96:e1:fe:94")
}
