import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_3A236F003Bdefc0C55Aa42D9C6C0B08E : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "02c95d8f-f694-5d0f-bf79-b806334e8af3"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L4522-L4533"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "9930b2d3fdbd2f6da17d78dfbfe6229f0bd004686e4cc4960720710241237e48"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "5ba147ebae6089f99823b1640c305b337b1a4c36"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Assurio" and pe.signatures[i].serial=="3a:23:6f:00:3b:de:fc:0c:55:aa:42:d9:c6:c0:b0:8e")
}
