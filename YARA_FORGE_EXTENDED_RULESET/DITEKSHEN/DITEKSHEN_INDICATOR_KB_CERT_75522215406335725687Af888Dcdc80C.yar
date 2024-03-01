import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_75522215406335725687Af888Dcdc80C : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "712d41e1-6760-5124-8af2-c57a87816237"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L614-L625"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "5166ea726b1be824e5702c411800236d60c44fbfc89a39b1bc103de965249d7d"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = ""
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "THEESOLUTIONS LTD" and pe.signatures[i].serial=="75:52:22:15:40:63:35:72:56:87:af:88:8d:cd:c8:0c")
}
