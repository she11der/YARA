import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_21144343720267Ba42F586105Ff279De : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "54e4133f-4fb7-5f70-a4dc-77c6f8120d29"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L6860-L6871"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "a1eacebed0966ad5d78eb7e38d8b854d183f21a19a53bbcb57503e4271b2cc84"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "c56f79b4cc3a0e0894cd1e54facdf2db9d8ca62a"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Varta Blue Dynamic" and pe.signatures[i].serial=="21:14:43:43:72:02:67:ba:42:f5:86:10:5f:f2:79:de")
}
