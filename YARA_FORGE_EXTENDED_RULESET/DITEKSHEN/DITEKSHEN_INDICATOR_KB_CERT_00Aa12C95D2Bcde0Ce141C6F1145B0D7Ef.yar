import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00Aa12C95D2Bcde0Ce141C6F1145B0D7Ef : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "66ef7681-7467-5c9f-8e0b-749a9711f15a"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L4257-L4268"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "34edd92640d8059f074513b526c7a2bf0d9265af9466a2ae66b93255044744c4"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "1383c4aa2900882f9892696c537e83f1fb20a43f"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "PROKON, OOO" and pe.signatures[i].serial=="00:aa:12:c9:5d:2b:cd:e0:ce:14:1c:6f:11:45:b0:d7:ef")
}
