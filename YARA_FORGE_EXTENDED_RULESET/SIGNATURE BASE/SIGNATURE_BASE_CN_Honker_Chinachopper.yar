rule SIGNATURE_BASE_CN_Honker_Chinachopper : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file ChinaChopper.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "9f7fbaac-65b5-5162-87d1-96ccd9711adb"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_tools.yar#L596-L612"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "fa347fdb23ab0b8d0560a0d20c434549d78e99b5"
		logic_hash = "e5e6a8a17592e7c82af830153905a52f8202a65c8e2f4b09dbebb19d04e2f8d7"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "$m=get_magic_quotes_gpc();$sid=$m?stripslashes($_POST[\"z1\"]):$_POST[\"z1\"];$u" wide
		$s3 = "SETP c:\\windows\\system32\\cmd.exe " fullword wide
		$s4 = "Ev al (\"Exe cute(\"\"On+Error+Resume+Next:%s:Response.Write(\"\"\"\"->|\"\"\"\"" wide

	condition:
		uint16(0)==0x5a4d and filesize <2000KB and 1 of them
}
