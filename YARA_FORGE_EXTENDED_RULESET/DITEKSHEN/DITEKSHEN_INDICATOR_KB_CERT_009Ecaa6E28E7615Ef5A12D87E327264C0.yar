import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_009Ecaa6E28E7615Ef5A12D87E327264C0 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "8fd9f4e8-4ec3-5731-8032-e2657ee229ca"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L5244-L5255"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "24858027f62fd057c06dbf58b4a6e1e5f1dcd9429676232a8e66d231e713f56a"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "50899ef5014af31cd54cb9a7c88659a6890b6954"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "HaqMkgGQmnNHpFsQmzMRDcavkPBzOcvMatDmcLHuDNoiQWMqj" and pe.signatures[i].serial=="00:9e:ca:a6:e2:8e:76:15:ef:5a:12:d8:7e:32:72:64:c0")
}
