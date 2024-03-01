import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_709D547A2F09D39C4C2334983F2Cbf50 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "e3b2ab8b-be90-5593-843f-59f2d626e604"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L4322-L4333"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "f45a2047181f3f07a8fb9cc00aafc31ba7aa369fc5c0165557757306a0de0d44"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "f10095c5e36e6bce0759f52dd11137756adc3b53"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "BMUZVYUGWSQWLAIISX" and pe.signatures[i].serial=="70:9d:54:7a:2f:09:d3:9c:4c:23:34:98:3f:2c:bf:50")
}
