import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00E38259Cf24Cc702Ce441B683Ad578911 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "79e00e92-4ddb-5f87-8f60-78f326674c66"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L1585-L1596"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "53d135553b88484e2c40976a9eaa0eb3f4f34c40ce775c198dfd6552155d1859"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "16304d4840d34a641f58fe7c94a7927e1ba4b3936638164525bedc5a406529f8"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Akhirah Technologies Inc." and pe.signatures[i].serial=="00:e3:82:59:cf:24:cc:70:2c:e4:41:b6:83:ad:57:89:11")
}
