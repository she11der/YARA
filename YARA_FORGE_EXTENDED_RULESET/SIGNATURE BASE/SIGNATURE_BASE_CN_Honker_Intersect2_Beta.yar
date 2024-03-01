rule SIGNATURE_BASE_CN_Honker_Intersect2_Beta : FILE
{
	meta:
		description = "Script from disclosed CN Honker Pentest Toolset - file Intersect2-Beta.py"
		author = "Florian Roth (Nextron Systems)"
		id = "d20da18d-f8c9-5eb3-8d5d-c8816cff3200"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_scripts.yar#L256-L272"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "3ba5f720c4994cd4ad519b457e232365e66f37cc"
		logic_hash = "bc6a83f8f851f7fb5b620be889619fcbd9f34ba27d495c2040e207caf95854bb"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "os.system(\"ls -alhR /home > AllUsers.txt\")" fullword ascii
		$s2 = "os.system('getent passwd > passwd.txt')" fullword ascii
		$s3 = "os.system(\"rm -rf credentials/\")" fullword ascii

	condition:
		uint16(0)==0x2123 and filesize <50KB and 2 of them
}
