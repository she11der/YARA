rule SIGNATURE_BASE__Hscan_Hscan_Hscangui : FILE
{
	meta:
		description = "Chinese Hacktool Set - from files hscan.exe, hscan.exe, hscangui.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "174b0ee4-23ce-59fd-a784-ab58fd13ce67"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_cn_hacktools.yar#L2499-L2519"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "5466c3dd8b2b777186bfab9d0948905eb3692ce05cf4748fb5b7b896dc3cb251"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash0 = "17a743e40790985ececf5c66eaad2a1f8c4cffe8"
		hash1 = "568b06696ea0270ee1a744a5ac16418c8dacde1c"
		hash2 = "af8aced0a78e1181f4c307c78402481a589f8d07"

	strings:
		$s1 = ".\\log\\Hscan.log" fullword ascii
		$s2 = ".\\report\\%s-%s.html" fullword ascii
		$s3 = "[%s]: checking \"FTP account: ftp/ftp@ftp.net\" ..." fullword ascii
		$s4 = "[%s]: IPC NULL session connection success !!!" fullword ascii
		$s5 = "Scan %d targets,use %4.1f minutes" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <240KB and all of them
}
