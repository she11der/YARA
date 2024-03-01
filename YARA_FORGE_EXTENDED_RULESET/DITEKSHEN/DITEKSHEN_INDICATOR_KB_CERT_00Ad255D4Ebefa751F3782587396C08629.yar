import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00Ad255D4Ebefa751F3782587396C08629 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "58e77872-5bd0-53b1-9595-c961c45e138c"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L5884-L5895"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "cc51de3852257b12a780f80755c7ca21f5d82542649c65072fd9427271da12ef"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "8fa4298057066c9ef96c28b2dd065e8896327658"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "OOO Ornitek" and pe.signatures[i].serial=="00:ad:25:5d:4e:be:fa:75:1f:37:82:58:73:96:c0:86:29")
}
