rule SIGNATURE_BASE_Marathontool : FILE
{
	meta:
		description = "Chinese Hacktool Set - file MarathonTool.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "23513361-ecac-5ddb-92b9-4dd8da12e8db"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_hacktools.yar#L69-L84"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "084a27cd3404554cc799d0e689f65880e10b59e3"
		logic_hash = "2d52d640ef44d933791d1da0d1263dba15702180c730500e04d364dd6b4d6081"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "MarathonTool" ascii
		$s17 = "/Blind SQL injection tool based in heavy queries" fullword ascii
		$s18 = "SELECT UNICODE(SUBSTRING((system_user),{0},1))" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <1040KB and all of them
}
