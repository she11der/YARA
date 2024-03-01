import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_56D576A062491Ea0A5877Ced418203A1 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "94e29354-b6bc-5936-abc8-2b42d2e65294"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L1780-L1791"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "877b773cb1bdc6c6c309374e95dc7eac4d525c681200169fcf492476f6335342"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "b22e022f030cf1e760a7df84d22e78087f3ea2ed262a4b76c8b133871c58213b"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Silvo LLC" and pe.signatures[i].serial=="56:d5:76:a0:62:49:1e:a0:a5:87:7c:ed:41:82:03:a1")
}
