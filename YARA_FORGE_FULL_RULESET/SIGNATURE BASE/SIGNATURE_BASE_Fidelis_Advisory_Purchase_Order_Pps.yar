rule SIGNATURE_BASE_Fidelis_Advisory_Purchase_Order_Pps
{
	meta:
		description = "Detects a string found in a malicious document named Purchase_Order.pps"
		author = "Florian Roth (Nextron Systems)"
		id = "205c4cda-6874-5455-8eb9-b63fb09b13fd"
		date = "2015-06-09"
		modified = "2023-12-05"
		reference = "http://goo.gl/ZjJyti"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_fidelis_phishing_plain_sight.yar#L2-L14"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "45cfee6413accff36a39ced861a29c611d6efe24e1ca87f17467106f8565642b"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "Users\\Gozie\\Desktop\\Purchase-Order.gif" ascii

	condition:
		all of them
}
