import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_3Ab74A2Ebf93447Adb83554B5564Fe03 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "1b0be137-ddcf-5215-9cb0-d687d7b6ca6c"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L7786-L7799"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "8dbc549ecaf1cb3f07486bac7ed265882af4b6b29b9772736118490eb9233303"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "8ed289fcc40bbc150a52b733123f6094ccfb2c499d6e932b0d9a6001490fb7e6"
		reason = "RedLineStealer"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "IMPERIOUS TECHNOLOGIES LIMITED" and pe.signatures[i].serial=="3a:b7:4a:2e:bf:93:44:7a:db:83:55:4b:55:64:fe:03")
}
