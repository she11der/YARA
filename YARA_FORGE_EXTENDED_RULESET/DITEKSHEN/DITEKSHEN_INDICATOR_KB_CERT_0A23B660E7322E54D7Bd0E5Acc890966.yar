import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_0A23B660E7322E54D7Bd0E5Acc890966 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "c9817cbd-edce-5ae0-ad70-58d592ac415f"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L198-L209"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "6b9009d0c509b38107eba5742613f8ec6f48e447225c664e374ef56d64b035f0"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "c1e0c6dc2bc8ea07acb0f8bdb09e6a97ae91e57c"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ARTBUD RADOM SP Z O O" and pe.signatures[i].serial=="0a:23:b6:60:e7:32:2e:54:d7:bd:0e:5a:cc:89:09:66")
}
