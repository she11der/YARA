import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_0092Bc051F1811Bb0B86727C36394F7849 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "9ffef880-ed00-54a7-8eb2-995c5c4e74f1"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L2783-L2794"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "bdf847f95bc6cc50513b76c57c3e76bc17caacd3419baabb2cab0161feb67508"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "d1f9930521e172526a9f018471d4575d60d8ad8f"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "MISTO EKONOMSKE STORITVE, d.o.o." and pe.signatures[i].serial=="00:92:bc:05:1f:18:11:bb:0b:86:72:7c:36:39:4f:78:49")
}
