import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_0989C97804C93Ec0004E2843 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "13b2dd06-878e-5539-91d1-eff8607997c3"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L967-L978"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "65b695eed221db86928ebd32a1f3cb35729754ba41cb2e5b6cf944890d211120"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "98549ae51b7208bda60b7309b415d887c385864b"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Shanghai Hintsoft Co., Ltd." and pe.signatures[i].serial=="09:89:c9:78:04:c9:3e:c0:00:4e:28:43")
}
