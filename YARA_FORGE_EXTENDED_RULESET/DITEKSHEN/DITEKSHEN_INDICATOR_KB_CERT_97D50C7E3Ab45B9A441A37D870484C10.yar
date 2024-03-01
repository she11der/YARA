import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_97D50C7E3Ab45B9A441A37D870484C10 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "54c391df-ea76-5944-aae6-63f44ec557e5"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L6931-L6942"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "2f535f66a4aabffff48f167ffcabcb366398e358eaafa2b3d67ee4c7ad19eb66"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "2e47ceb6593c9fdbd367da8b765090e48f630b33"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SHENZHEN MINIWAN TECHNOLOGY CO. LTD." and pe.signatures[i].serial=="97:d5:0c:7e:3a:b4:5b:9a:44:1a:37:d8:70:48:4c:10")
}
