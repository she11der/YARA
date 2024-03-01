import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_105765998695197De4109828A68A4Ee0 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "97a4bad1-9b84-54e3-a1c2-6d01bd4cde4c"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L2664-L2675"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "c251f28eec6f93522f5a3706e1abcfd892affa2b36ed84ec277dc0d4716ff667"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "5ddae14820d6f189e637f90b81c4fdb78b5419dc"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Cryptonic ApS" and pe.signatures[i].serial=="10:57:65:99:86:95:19:7d:e4:10:98:28:a6:8a:4e:e0")
}
