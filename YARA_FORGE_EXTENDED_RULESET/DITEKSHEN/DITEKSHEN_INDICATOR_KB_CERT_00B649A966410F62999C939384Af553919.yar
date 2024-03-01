import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00B649A966410F62999C939384Af553919 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "6b88b712-6d25-5152-80bf-562bf82f336c"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L1611-L1622"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "231b0aa0a1e7c72552d683cc4f93b39444f7c1ebb3bb719bee224aa62e9a28dd"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "a0c6cd25e1990c0d03b6ec1ad5a140f2c8014a8c2f1f4f227ee2597df91a8b6c"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "F.A.T. SARL" and pe.signatures[i].serial=="00:b6:49:a9:66:41:0f:62:99:9c:93:93:84:af:55:39:19")
}
