import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_66F98881Fbb02D0352Bef7C13Bd61Df2 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "9cc569f4-1686-5f17-99a4-90750023d519"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L5283-L5294"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		hash = "f265524fb9a4a58274dbd32b2ed0c3f816c5eff05e1007a2e7bba286b8ffa72c"
		logic_hash = "3d70da3f644a90bc6e7b405a41225a328d7007187525a0b277f0fc1136be8b5b"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "722eee34153fc67ea7abdcb0c6e9e54479f1580e"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].serial=="66:f9:88:81:fb:b0:2d:03:52:be:f7:c1:3b:d6:1d:f2")
}
