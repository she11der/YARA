import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_0Ced87Bd70B092Cb93B182Fac32655F6 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "5e716e70-0c78-5194-9134-0ee140221610"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L5499-L5511"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		hash = "083d5efb4da09432a206cb7fba5cef2c82dd6cc080015fe69c2b36e71bca6c89"
		logic_hash = "3d4d84a60095e608fbd774f2b3a0f86e32dd9fe25801da06ee10188425a029e0"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "97b7602ed71480756cf6e4658a107f8278a48096"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Creator Soft Limited" and pe.signatures[i].serial=="0c:ed:87:bd:70:b0:92:cb:93:b1:82:fa:c3:26:55:f6")
}
