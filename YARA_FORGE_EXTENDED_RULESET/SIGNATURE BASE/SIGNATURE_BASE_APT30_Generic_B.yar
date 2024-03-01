rule SIGNATURE_BASE_APT30_Generic_B : FILE
{
	meta:
		description = "FireEye APT30 Report Sample"
		author = "Florian Roth (Nextron Systems)"
		id = "df3b8896-7229-5b3b-ad2f-774b0cea167c"
		date = "2015-04-13"
		modified = "2023-12-05"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_apt30_backspace.yar#L203-L222"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "527c823607836f138369224b7d8d492d36d9ab7a150e64fd5ebbaf99538d6d53"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "0fcb4ffe2eb391421ec876286c9ddb6c"
		hash2 = "29395c528693b69233c1c12bef8a64b3"
		hash3 = "4c6b21e98ca03e0ef0910e07cef45dac"
		hash4 = "550459b31d8dabaad1923565b7e50242"
		hash5 = "65232a8d555d7c4f7bc0d7c5da08c593"
		hash6 = "853a20f5fc6d16202828df132c41a061"
		hash7 = "ed151602dea80f39173c2f7b1dd58e06"

	strings:
		$s2 = "Moziea/4.0" ascii

	condition:
		filesize <100KB and uint16(0)==0x5A4D and all of them
}
