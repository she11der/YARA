import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00A7989F8Be0C82D35A19E7B3Dd4Be30E5 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "0bb81ddc-b63b-534b-852f-7b0a2feeef9e"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L1650-L1661"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "66d600d97b5aca1aa9a302671f06aef0d5c4ae9829d6cb16f191bd4c59462d2e"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "3e93aadb509b542c065801f04cffb34956f84ee8c322d65c7ae8e23d27fe5fbf"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Instamix Limited" and pe.signatures[i].serial=="00:a7:98:9f:8b:e0:c8:2d:35:a1:9e:7b:3d:d4:be:30:e5")
}
