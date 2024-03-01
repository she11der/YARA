import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_11A9Bf6B2Dcbc683475B431A1C79133E : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "9c49f529-330f-5d37-b613-e45aad50afcb"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L5604-L5615"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "fa424180e60d2fde2fce085d0c848c5b33bcc58c2ca54f327f446ff5cf361fe2"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "7412b3f5ba689967a5b46e6ef5dc5e9b9de3917d"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "BINDOX" and pe.signatures[i].serial=="11:a9:bf:6b:2d:cb:c6:83:47:5b:43:1a:1c:79:13:3e")
}
