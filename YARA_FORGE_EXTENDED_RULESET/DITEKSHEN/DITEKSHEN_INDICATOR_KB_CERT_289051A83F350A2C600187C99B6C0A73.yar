import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_289051A83F350A2C600187C99B6C0A73 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "f84a7749-a487-52e5-813b-e376ccde13d1"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L6418-L6429"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "f094e923dc53cc1edc6ac83cf69fb60fd3c564606a5bfb68facb482918399799"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "4e075adea8c1bcb9d10904203ab81965f4912ff0"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "HALL HAULAGE LTD LTD" and pe.signatures[i].serial=="28:90:51:a8:3f:35:0a:2c:60:01:87:c9:9b:6c:0a:73")
}
