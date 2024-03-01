import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00801689896Ed339237464A41A2900A969 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "91cecd18-0007-59a4-94f3-bdaa06b25822"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L5552-L5563"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "9dc505e00e0085587aee2bf2e70db04850e11d057b8d16e31e8caebb130e047b"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "9b0ab2e7f3514f6372d14b1f7f963c155b18bd24"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "GLG Rental ApS" and pe.signatures[i].serial=="00:80:16:89:89:6e:d3:39:23:74:64:a4:1a:29:00:a9:69")
}
