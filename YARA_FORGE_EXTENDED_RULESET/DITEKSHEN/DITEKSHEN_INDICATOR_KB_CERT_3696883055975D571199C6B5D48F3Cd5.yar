import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_3696883055975D571199C6B5D48F3Cd5 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "8af62be2-488f-5474-b674-73bf157dff00"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L2027-L2038"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "9232413a071a6100ba806b1fad2cd6cd2bb85351c36ad25cfc31b66ad041d686"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "933749369d61bebd5f2c63ff98625973c41098462d9732cffaffe7e02823bc3a"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Korist Networks Incorporated" and pe.signatures[i].serial=="36:96:88:30:55:97:5d:57:11:99:c6:b5:d4:8f:3c:d5")
}
