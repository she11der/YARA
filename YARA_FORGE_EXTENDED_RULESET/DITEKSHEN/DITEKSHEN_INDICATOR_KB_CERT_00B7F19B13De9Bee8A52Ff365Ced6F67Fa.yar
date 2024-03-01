import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00B7F19B13De9Bee8A52Ff365Ced6F67Fa : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "b9cbe1bd-b24f-5599-a8b9-9e6f9b70f37f"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L172-L183"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "afdc41aed0480593bb8c92955db044ebe1a695d4912176123e26e052a3e9d3ea"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "61708a3a2bae5343ff764de782d7f344151f2b74"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ALEXIS SECURITY GROUP, LLC" and pe.signatures[i].serial=="00:b7:f1:9b:13:de:9b:ee:8a:52:ff:36:5c:ed:6f:67:fa")
}
