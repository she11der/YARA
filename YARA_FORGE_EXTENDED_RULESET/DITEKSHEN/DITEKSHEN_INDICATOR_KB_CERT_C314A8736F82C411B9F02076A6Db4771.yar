import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_C314A8736F82C411B9F02076A6Db4771 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "0a8af16c-f232-5e09-9825-0e8203ba7b45"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L3620-L3631"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "8aa08c4d1da62d0629db6e29f7a730da3534f114620e30f8d89e5475c12f43de"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "9c49d7504551ad4ddffad206b095517a386e8a14"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Cbcbaeaabbfcebfcbbeeffeadfc" and pe.signatures[i].serial=="c3:14:a8:73:6f:82:c4:11:b9:f0:20:76:a6:db:47:71")
}
