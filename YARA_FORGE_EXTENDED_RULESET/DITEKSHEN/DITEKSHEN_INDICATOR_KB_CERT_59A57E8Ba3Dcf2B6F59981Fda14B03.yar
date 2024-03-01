import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_59A57E8Ba3Dcf2B6F59981Fda14B03 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "07e68e53-ffb8-5f12-ad0e-cf64a3c9cb72"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L5828-L5841"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "1eeeef14502daafb303d1c09d8e55fb4df57a6bf250d1adc7e53862f2f5d5824"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "e201821e152d7ae86078c4e6a3a3a1e1c5e29f9a"
		hash1 = "d9ace2d97010316fdb0f416920232e8d4c59b01614633c4d5def79abb15d0175"
		hash2 = "80e363dee08f4f77e5a061c10f18503c7ce802818cf6bb1c8a16da0ba3877b01"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Medium LLC" and pe.signatures[i].serial=="59:a5:7e:8b:a3:dc:f2:b6:f5:99:81:fd:a1:4b:03")
}
