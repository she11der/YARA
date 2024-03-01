import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_3112C69D460C781Fd649C71E61Bfec82 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "a8092e36-92f9-5cb0-a427-74d40a39d94f"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L6512-L6523"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "9662a01369bc01367bcae7813b3fcb3050721471dd247885bcab8918de7c6b99"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "7ec961d2c69f7686e33f39d497a5e3039e512cf3"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "KREATURHANDLER BJARNE ANDERSEN ApS" and pe.signatures[i].serial=="31:12:c6:9d:46:0c:78:1f:d6:49:c7:1e:61:bf:ec:82")
}
