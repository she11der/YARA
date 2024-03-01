import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_3A9Bdec10E00E780316Baaebfe7A772C : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "0879b4f7-4058-5391-b8bf-90a46ef337f6"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L941-L952"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "f1c0d23c9aa2ff705e3350e15b7ff83fc007ce6aaa57c4ed59201f3022f5d00a"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "981b95ffcb259862e7461bc58516d7785de91a8a"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "PLAN ALPHA LIMITED" and pe.signatures[i].serial=="3a:9b:de:c1:0e:00:e7:80:31:6b:aa:eb:fe:7a:77:2c")
}
