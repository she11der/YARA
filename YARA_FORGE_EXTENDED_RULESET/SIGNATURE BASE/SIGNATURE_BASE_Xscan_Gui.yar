rule SIGNATURE_BASE_Xscan_Gui : FILE
{
	meta:
		description = "Chinese Hacktool Set - file xscan_gui.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "fee11058-e75f-5d8f-8d10-06dcaed99df1"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_hacktools.yar#L1754-L1770"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "a9e900510396192eb2ba4fb7b0ef786513f9b5ab"
		logic_hash = "366db7eb19725a0a42ce371d7bfb50a22a259f0bc0252927af626e8c1c0b9b59"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "%s -mutex %s -host %s -index %d -config \"%s\"" fullword ascii
		$s2 = "www.target.com" fullword ascii
		$s3 = "%s\\scripts\\desc\\%s.desc" fullword ascii
		$s4 = "%c Active/Maximum host thread: %d/%d, Current/Maximum thread: %d/%d, Time(s): %l" ascii

	condition:
		uint16(0)==0x5a4d and filesize <3000KB and all of them
}
