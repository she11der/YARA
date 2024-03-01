import "pe"

rule CAPE_Nighthawk
{
	meta:
		description = "NightHawk C2"
		author = "Nikhil Ashok Hegde <@ka1do9>"
		id = "096b9d13-6aa7-5b6e-aaeb-e25aa7c8c53f"
		date = "2022-12-05"
		modified = "2022-12-05"
		reference = "https://github.com/kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/ef54cd63832eb05a5e502bbd6dd9217938d66a5d/data/yara/CAPE/Nighthawk.yar#L3-L24"
		license_url = "https://github.com/kevoreilly/CAPEv2/blob/ef54cd63832eb05a5e502bbd6dd9217938d66a5d/LICENSE"
		logic_hash = "2d77912678e06503ffef0e8ed84aa4f9ac74357480d57742fbae619acebfb5f2"
		score = 75
		quality = 70
		tags = ""
		cape_type = "Nighthawk Payload"

	strings:
		$keying_methods = { 85 C9 74 43 83 E9 01 74 1C 83 F9 01 0F 85 }
		$aes_sbox = { 63 7C 77 7B F2 6B 6F C5 30 }
		$aes_inv_sbox = { 52 09 6A D5 30 36 A5 38 BF }

	condition:
		pe.is_pe and for any s in pe.sections : (s.name==".profile") and all of them
}
