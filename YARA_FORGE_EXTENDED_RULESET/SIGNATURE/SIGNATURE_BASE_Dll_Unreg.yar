rule SIGNATURE_BASE_Dll_Unreg : FILE
{
	meta:
		description = "Chinese Hacktool Set - file UnReg.bat"
		author = "Florian Roth (Nextron Systems)"
		id = "5c14486d-72a2-5a18-9db0-ce0ab61fdce7"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_hacktool_scripts.yar#L60-L74"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "d5e24ba86781c332d0c99dea62f42b14e893d17e"
		logic_hash = "0e534e475a5b4338aa53bea09325dd63a3d451a13b46a70b5208cabd2deecabe"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "regsvr32.exe /u C:\\windows\\system32\\PacketX.dll" fullword ascii
		$s1 = "del /F /Q C:\\windows\\system32\\PacketX.dll" fullword ascii

	condition:
		filesize <1KB and 1 of them
}
