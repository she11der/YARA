import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00A3Cb8E964244768969B837Ca9981De68 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "a9d74cc6-0d89-5de9-8f13-966455e49b9c"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L6873-L6884"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "d88c9ac03a4b3803b85c5ee30ad127aca43cbfc33d754bc42c15593f7294b1bc"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "5617114bc2a584532eba1dd9eb9d23108d1f9ea7"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].serial=="a3:cb:8e:96:42:44:76:89:69:b8:37:ca:99:81:de:68" or pe.signatures[i].serial=="00:a3:cb:8e:96:42:44:76:89:69:b8:37:ca:99:81:de:68")
}
