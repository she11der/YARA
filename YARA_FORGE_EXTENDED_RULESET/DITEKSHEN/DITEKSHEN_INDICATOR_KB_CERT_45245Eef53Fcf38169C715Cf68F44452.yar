import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_45245Eef53Fcf38169C715Cf68F44452 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "3e92744d-1eb8-511a-b933-6dbe1e74fcfd"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L8896-L8909"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "7667563aa02be9a85ba286bc16eb37380d5988b32f0ce27b1dbd9ae18b8b9175"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "ad7edb1b0a6a1ee3297a8825aff090030142dce8b59b9261bc57ca86666b0cbe"
		reason = "QuakBot"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "PAPER AND CORE SUPPLIES LTD" and pe.signatures[i].serial=="45:24:5e:ef:53:fc:f3:81:69:c7:15:cf:68:f4:44:52")
}
