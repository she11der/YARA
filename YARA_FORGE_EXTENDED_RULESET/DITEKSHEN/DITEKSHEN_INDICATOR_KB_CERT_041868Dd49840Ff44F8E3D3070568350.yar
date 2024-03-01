import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_041868Dd49840Ff44F8E3D3070568350 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "2cfbae1f-9c8a-5263-b9d6-5be27fdca822"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L4023-L4034"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "80abb596d96cb388bf3ff23598fc889d4c14cccf262d01f10a5be3a738a4907e"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "e104f236e3ee7d21a0ea8053fe8fc5c412784079"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Zhuhai Kingsoft Office Software Co., Ltd." and pe.signatures[i].serial=="04:18:68:dd:49:84:0f:f4:4f:8e:3d:30:70:56:83:50")
}
