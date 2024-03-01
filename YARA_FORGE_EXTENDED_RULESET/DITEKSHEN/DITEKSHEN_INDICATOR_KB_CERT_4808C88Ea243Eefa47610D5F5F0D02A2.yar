import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_4808C88Ea243Eefa47610D5F5F0D02A2 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "ea3aadc6-3edd-5e4b-adfe-824103531deb"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L3030-L3041"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "9fa722bfed0c31e263772615799bbdc054da1424b139c7d73e5755334fb86346"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "5dc400de1133be3ff17ff09f8a1fd224b3615e5a"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Bfcdcdfcdfcaaeff" and pe.signatures[i].serial=="48:08:c8:8e:a2:43:ee:fa:47:61:0d:5f:5f:0d:02:a2")
}
