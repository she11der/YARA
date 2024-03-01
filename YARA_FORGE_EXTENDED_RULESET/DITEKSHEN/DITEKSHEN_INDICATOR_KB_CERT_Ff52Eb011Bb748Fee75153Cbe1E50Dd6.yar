import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_Ff52Eb011Bb748Fee75153Cbe1E50Dd6 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "452d9f84-a950-5503-adaf-fba95b45e798"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L8296-L8309"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "e439f15c3312ed3a1840967bb165300a491ffe3d1c9c629abcbebf3efd9b1f50"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "c75025c80ab583a6ab87070e5b65c93cb59b48e0cbb5f99113e354a96f8fcd39"
		reason = "Quakbot"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "TASK ANNA LIMITED" and pe.signatures[i].serial=="ff:52:eb:01:1b:b7:48:fe:e7:51:53:cb:e1:e5:0d:d6")
}
