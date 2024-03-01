import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00A496Bc774575C31Abec861B68C36Dcb6 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "2415bf62-15d4-562a-a448-682474d89af0"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L3854-L3865"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "bf5282687f4707bc16d388361ddc0af1102df0d29066ece0b57215fcf9fdcc94"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "b2c70d30c0b34bfeffb8a9cb343e5cad5f6bcbf7"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ORGLE DVORSAK, d.o.o" and pe.signatures[i].serial=="00:a4:96:bc:77:45:75:c3:1a:be:c8:61:b6:8c:36:dc:b6")
}
