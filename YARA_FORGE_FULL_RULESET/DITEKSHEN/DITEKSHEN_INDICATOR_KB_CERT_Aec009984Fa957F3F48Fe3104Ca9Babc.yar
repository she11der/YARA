import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_Aec009984Fa957F3F48Fe3104Ca9Babc : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "76b5d6b6-f443-55b5-b353-88201fe09e1f"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L3438-L3449"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "de9008e30468b94b4afbc622403b0257f5c5e3964344b980c18fc95219e06667"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "9d5b6bc86775395992a25d21d696d05d634a89d1"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Ceefaccdedbfbbaaaadacdbf" and pe.signatures[i].serial=="ae:c0:09:98:4f:a9:57:f3:f4:8f:e3:10:4c:a9:ba:bc")
}
