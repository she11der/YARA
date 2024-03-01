rule SIGNATURE_BASE_Molerats_Jul17_Sample_2 : FILE
{
	meta:
		description = "Detects Molerats sample - July 2017"
		author = "Florian Roth (Nextron Systems)"
		id = "7ef02003-83d1-5ec7-952d-1e693375dd4b"
		date = "2017-07-07"
		modified = "2023-12-05"
		reference = "https://mymalwareparty.blogspot.de/2017/07/operation-desert-eagle.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_molerats_jul17.yar#L27-L42"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "35a517039474dcc5d503a48ca17e544166ee2ed44417ea5e7711093d3956f80c"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "7e122a882d625f4ccac019efb7bf1b1024b9e0919d205105e7e299fb1a20a326"

	strings:
		$s1 = "Folder.exe" fullword ascii
		$s2 = "Notepad++.exe" fullword wide
		$s3 = "RSJLRSJOMSJ" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <1000KB and all of them )
}
