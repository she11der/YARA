import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_082023879112289Bf351D297Cc8Efcfc : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "292f99be-2eb0-5ad1-bd07-766de7822f1e"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L2430-L2441"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "0747b37139daaba10a17098aeb0c6246290fbd997345de34ce9de8da26d7db05"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "0eb3382177f26e122e44ddd74df262a45ebe8261029bc21b411958a07b06278a"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "STA-R TOV" and pe.signatures[i].serial=="08:20:23:87:91:12:28:9b:f3:51:d2:97:cc:8e:fc:fc")
}
