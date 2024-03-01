import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_62205361A758B00572D417Cba014F007 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "7838c733-7212-5e86-bb3c-5dfefb727a4b"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L1845-L1856"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "52d67bc94e82bb9a36e969d393c395465c84ff76f89c5f8407c20e2c761000e3"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "83e851e8c50f9d7299363181f2275edc194037be8cb6710762d2099e0b3f31c6"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "UNITEKH-S, OOO" and pe.signatures[i].serial=="62:20:53:61:a7:58:b0:05:72:d4:17:cb:a0:14:f0:07")
}
