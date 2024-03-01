rule SIGNATURE_BASE_Pw_Inspector : FILE
{
	meta:
		description = "Chinese Hacktool Set - file pw-inspector.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "888db647-c5d0-5b1b-bcd2-512c1ebeadea"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_cn_hacktools.yar#L567-L582"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "4f8e3e101098fc3da65ed06117b3cb73c0a66215"
		logic_hash = "3b54466d80692923b93689a9e43e30dfbc63e5982cb633120795817098d68e05"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "-m MINLEN  minimum length of a valid password" fullword ascii
		$s2 = "http://www.thc.org" fullword ascii
		$s3 = "Use for hacking: trim your dictionary file to the pw requirements of the target." fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <460KB and all of them
}
