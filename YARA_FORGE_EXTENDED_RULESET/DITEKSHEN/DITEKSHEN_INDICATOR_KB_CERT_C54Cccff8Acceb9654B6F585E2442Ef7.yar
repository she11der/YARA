import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_C54Cccff8Acceb9654B6F585E2442Ef7 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "c199b65f-5e95-5c6a-8ccc-7f343b867885"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L1728-L1739"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "4be5e0f9f522f0d4096a63b001a02ea130ef56149dec7f0ac90be686b885cc4a"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "416c79fccc5f42260cd227fd831b001aca14bf0d"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Eadbebdebcc" and pe.signatures[i].serial=="c5:4c:cc:ff:8a:cc:eb:96:54:b6:f5:85:e2:44:2e:f7")
}
