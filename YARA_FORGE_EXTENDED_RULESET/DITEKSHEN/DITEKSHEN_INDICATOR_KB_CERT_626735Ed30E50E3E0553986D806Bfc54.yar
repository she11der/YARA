import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_626735Ed30E50E3E0553986D806Bfc54 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "5cab852e-8483-5c38-a396-3a53cf64450a"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L8101-L8114"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "960005fe1a28ddb50261aeaaa850a2410ac03ee9709af2a75485313676c92c53"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "a1488004ec967faf6c66f55440bbde0de47065490f7c758f3ca1315bb0ef3b97"
		reason = "Quakbot"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "FISH ACCOUNTING & TRANSLATING LIMITED" and pe.signatures[i].serial=="62:67:35:ed:30:e5:0e:3e:05:53:98:6d:80:6b:fc:54")
}
