import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_Dca9012634E8B609884Fe9284D30Eff5 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "f22ef616-c7f1-5036-b303-ef8ae038ec4f"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L3176-L3189"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "b5d663228a27d5dae46f9f03bd04833b129fc453852cb9cb9fe43e405cdcecca"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "60971c18c7efb4a294f1d8ee802ff3d581c77834"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Bebaeefaeba" and (pe.signatures[i].serial=="dc:a9:01:26:34:e8:b6:09:88:4f:e9:28:4d:30:ef:f5" or pe.signatures[i].serial=="00:dc:a9:01:26:34:e8:b6:09:88:4f:e9:28:4d:30:ef:f5"))
}
