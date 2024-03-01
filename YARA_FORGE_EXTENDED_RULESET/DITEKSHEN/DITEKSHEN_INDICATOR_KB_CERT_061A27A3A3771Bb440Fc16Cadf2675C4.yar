import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_061A27A3A3771Bb440Fc16Cadf2675C4 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "ef600135-6f5d-59a9-b387-60e8eb97cbf9"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L8386-L8399"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "d85b9d2b6fe4ce99670a8f51e84d63f1ec6d0341a3715eeed3e3d6a0fda93dc5"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "9ed703ba7033af5f88a5f5ef0155adc41715d3175eec836822a09a93d56e4b7f"
		reason = "Matanbuchus"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Westeast Tech Consulting, Corp." and pe.signatures[i].serial=="06:1a:27:a3:a3:77:1b:b4:40:fc:16:ca:df:26:75:c4")
}
