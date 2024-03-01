import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00D338F8A490E37E6C2Be80A0E349929Fa : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "5bb542de-637f-58a4-b96a-f20dba7be1b7"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L3685-L3696"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "ed7a48df55f2d7873795470b9074421f4008d715db07978c79b174fc3f2a801a"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "480a9ce15fc76e03f096fda5af16e44e0d6a212d6f09a898f51ad5206149bbe1"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SAGUARO ApS" and pe.signatures[i].serial=="00:d3:38:f8:a4:90:e3:7e:6c:2b:e8:0a:0e:34:99:29:fa")
}
