import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_53F575F7C33Ee007887F30680486Db5E : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "8353ac89-1d98-5b05-a851-50d9e42f8f74"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L2677-L2688"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "050d8c4dcb80cd637981c208c6d1316e9933d4f06bbf8af3717d2205a4f84f6d"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "a42d8f60663dd86265e566f33d0ed5554e4c9a50"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "RET PTY. LTD." and pe.signatures[i].serial=="53:f5:75:f7:c3:3e:e0:07:88:7f:30:68:04:86:db:5e")
}
