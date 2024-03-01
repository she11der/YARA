import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_Vmprotect_Client : FILE
{
	meta:
		description = "VMProtect Client Certificate"
		author = "ditekSHen"
		id = "f9fd6478-0fe5-54b6-ba33-79c02eb9ad04"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L6444-L6455"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "d55d9fe608d5ff357a3bcf700a3d8bd9556f83c7c792b50d2276228a77209346"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint1 = "2e20b7079e5d83e7987b2605db160d1561a0c07a"
		hash1 = "284dc48fc2a66a1071117e5f7b2ad68fba4aae69f31cf68b6b950e6205b52dc0"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "VMProtect Client ")
}
