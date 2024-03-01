import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_56Fff139Df5Ae7E788E5D72196Dd563A : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "7cdca79f-5bf3-5768-b034-4d3bb177ffc9"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L3919-L3930"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "022fd24ba023dba06f1c63d1d1c90d17dc82b060d634a27b237d37e37455964f"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "0f69ccb73a6b98f548d00f0b740b6e42907efaad"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Cifromatika LLC" and pe.signatures[i].serial=="56:ff:f1:39:df:5a:e7:e7:88:e5:d7:21:96:dd:56:3a")
}
