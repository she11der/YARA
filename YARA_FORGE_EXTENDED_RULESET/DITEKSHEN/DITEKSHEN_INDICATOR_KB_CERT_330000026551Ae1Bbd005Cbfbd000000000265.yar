import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_330000026551Ae1Bbd005Cbfbd000000000265 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "7f86e427-110f-5bcc-bb53-ca534f7444fc"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L7337-L7351"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "ae836069665d088c6a309efe5166e260836dce6398c51701b2274515bdaa2cbd"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "e168609353f30ff2373157b4eb8cd519d07a2bff"
		hash1 = "a471fdf6b137a6035b2a2746703cd696089940698fd533860d34e71cc6586850"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Microsoft Windows" and pe.signatures[i].issuer contains "Microsoft Windows Production PCA 2011" and pe.signatures[i].serial=="33:00:00:02:65:51:ae:1b:bd:00:5c:bf:bd:00:00:00:00:02:65" and 1614796238<=pe.signatures[i].not_after)
}
