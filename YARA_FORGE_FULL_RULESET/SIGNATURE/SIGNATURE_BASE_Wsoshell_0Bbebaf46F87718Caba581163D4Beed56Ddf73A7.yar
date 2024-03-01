rule SIGNATURE_BASE_Wsoshell_0Bbebaf46F87718Caba581163D4Beed56Ddf73A7 : FILE
{
	meta:
		description = "Detects a web shell"
		author = "Florian Roth (Nextron Systems)"
		id = "92165645-5392-588d-ba2a-5ef6b7499a5a"
		date = "2016-09-10"
		modified = "2023-12-05"
		reference = "https://github.com/bartblaze/PHP-backdoors"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L9627-L9641"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "bf5090fb909fea690c8a2af3cca35136eda3b9773976189158c25fb8877cc266"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "d053086907aed21fbb6019bf9e644d2bae61c63563c4c3b948d755db3e78f395"

	strings:
		$s8 = "$default_charset='Wi'.'ndo.'.'ws-12'.'51';" fullword ascii
		$s9 = "$mosimage_session = \"" fullword ascii

	condition:
		( uint16(0)==0x3f3c and filesize <300KB and all of them )
}
