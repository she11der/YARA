import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_65Cfd8419D70Ce4011D97Bc79D18315E : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "2368b3d1-1cd5-575b-a3ff-270349563d1a"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L7951-L7964"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "675ab6ef0f744f62db892992c6b3614e14b95f64e2800a0d10e55b915a2b4e74"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "7cff10e37a43843e971f02ca6ad6510f08a5209d21745181fc4d003a8287cd1b"
		reason = "BumbleBee"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "FACE AESTHETICS LTD" and pe.signatures[i].serial=="65:cf:d8:41:9d:70:ce:40:11:d9:7b:c7:9d:18:31:5e")
}
