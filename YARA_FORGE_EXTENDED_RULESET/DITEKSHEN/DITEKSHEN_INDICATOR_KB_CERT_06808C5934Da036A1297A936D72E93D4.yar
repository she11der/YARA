import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_06808C5934Da036A1297A936D72E93D4 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "c75ae0da-e8b9-581f-bfde-f23b3b3f9d22"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L6918-L6929"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "45840d354dcea86c38effc86b3b6f92540f32eab78286d51ff7f472618accb8b"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "efb70718bc00393a01694f255a28e30e9d2142a4"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Rhaon Entertainment Inc" and pe.signatures[i].serial=="06:80:8c:59:34:da:03:6a:12:97:a9:36:d7:2e:93:d4")
}
