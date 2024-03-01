import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_1389C8373C00B792207Bca20Aa40Aa40 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "7f22411b-6e66-5177-8837-12b82b3b916b"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L549-L560"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "5c0c9ca9e1179f253f1b2ecd9c8a1a0ed17345eb9830201c7c16050339d7ccbc"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "38f65d64ac93f080b229ab83cb72619b0754fa6f"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "VITA-DE d.o.o." and pe.signatures[i].serial=="13:89:c8:37:3c:00:b7:92:20:7b:ca:20:aa:40:aa:40")
}
