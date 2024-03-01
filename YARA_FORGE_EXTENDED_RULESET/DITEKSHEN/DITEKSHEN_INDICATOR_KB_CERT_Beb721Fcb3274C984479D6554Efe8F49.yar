import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_Beb721Fcb3274C984479D6554Efe8F49 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "311b4a7a-3185-5c61-961e-bd7d9bca28dd"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L5858-L5869"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "fdb28b4f8cf79d067ee8dcfc3109ceae38f7952c6fb34e61f489924d97d67151"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "2d1fd0cce4aa7e7dc6dd114a301825a7b8e887cf"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "CONFUSER" and pe.signatures[i].serial=="be:b7:21:fc:b3:27:4c:98:44:79:d6:55:4e:fe:8f:49")
}
