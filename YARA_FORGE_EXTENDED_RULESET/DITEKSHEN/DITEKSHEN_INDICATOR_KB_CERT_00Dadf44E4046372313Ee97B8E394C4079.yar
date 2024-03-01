import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00Dadf44E4046372313Ee97B8E394C4079 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "bb7178f4-079f-5f7e-9761-3f73203603c7"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L1962-L1973"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "e4480ad6ce302a87e38915ef7ba09a94a4626ed359333276b899474f21d46238"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "80986ae0d4f8c8fabf6c4a91550c90224e26205a4ca61c00ff6736dd94817e65"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Digital Capital Management Ireland Limited" and pe.signatures[i].serial=="00:da:df:44:e4:04:63:72:31:3e:e9:7b:8e:39:4c:40:79")
}
