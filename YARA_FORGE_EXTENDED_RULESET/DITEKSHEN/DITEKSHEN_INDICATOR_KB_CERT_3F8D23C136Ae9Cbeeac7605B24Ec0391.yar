import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_3F8D23C136Ae9Cbeeac7605B24Ec0391 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "86617b78-86b0-59dc-a072-cb4acecd60e1"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L4565-L4576"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "f074e141e07cbf6b5b4726b52faa382b8ece809804dcfb9d45a5b2450125b5b7"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "ff481ea6a887f3b5b941ff7d99a6cdf90c814c40"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Bandicam Company" and pe.signatures[i].serial=="3f:8d:23:c1:36:ae:9c:be:ea:c7:60:5b:24:ec:03:91")
}
