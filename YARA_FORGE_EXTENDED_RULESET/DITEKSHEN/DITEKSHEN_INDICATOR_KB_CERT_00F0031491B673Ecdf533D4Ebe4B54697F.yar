import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00F0031491B673Ecdf533D4Ebe4B54697F : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "ad027dc9-14bc-50dd-b260-7672c528ef9a"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L2952-L2963"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "4697ce0a7fcd1fa6ac1dd5246f2a23b85865bef4010280c4ca2e12c433b8ceb2"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "01e201cce1024237978baccf5b124261aa5edb01"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Eebbffbceacddbfaeefaecdbaf" and pe.signatures[i].serial=="00:f0:03:14:91:b6:73:ec:df:53:3d:4e:be:4b:54:69:7f")
}
