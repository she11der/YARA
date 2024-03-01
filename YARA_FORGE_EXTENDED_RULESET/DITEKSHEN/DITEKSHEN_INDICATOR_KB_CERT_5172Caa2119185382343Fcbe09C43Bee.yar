import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_5172Caa2119185382343Fcbe09C43Bee : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "54f38317-2d36-54ec-a3fc-04f8b0fc5529"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L3763-L3774"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "7aa1447bd0ac43ac29ed69bd6618c3695bfb50517a7ffce7d4e793ae0c5e0fa6"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "fd9b3f6b0eb9bd9baf7cbdc79ae7979b7ddad770"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Aefcdac" and pe.signatures[i].serial=="51:72:ca:a2:11:91:85:38:23:43:fc:be:09:c4:3b:ee")
}
