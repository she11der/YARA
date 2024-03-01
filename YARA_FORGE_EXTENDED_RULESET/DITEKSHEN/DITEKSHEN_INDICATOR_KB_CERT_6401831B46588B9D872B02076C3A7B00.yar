import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_6401831B46588B9D872B02076C3A7B00 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "d651bbe4-7e50-51bc-8f96-a78b11846699"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L5923-L5934"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "9a90c9d51dd6eb37bb3b6b17c5e3e5ebb6b6922efa14e3d8d60e72bcdb7b7259"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "19fc95ac815865e8b57c80ed21a22e2c0fecc1ff"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ACTIV GROUP ApS" and pe.signatures[i].serial=="64:01:83:1b:46:58:8b:9d:87:2b:02:07:6c:3a:7b:00")
}
