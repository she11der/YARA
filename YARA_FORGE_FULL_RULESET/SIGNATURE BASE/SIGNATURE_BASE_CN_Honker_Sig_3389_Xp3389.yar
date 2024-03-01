rule SIGNATURE_BASE_CN_Honker_Sig_3389_Xp3389 : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file xp3389.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "75d23c63-ba9e-55fd-90fe-5e054d28a777"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_tools.yar#L2055-L2071"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "d776eb7596803b5b94098334657667d34b60d880"
		logic_hash = "7fd7947a802a65dfd63ece3fc6eaf2da8207e99276a9f6b1ff2c937cf4327945"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "echo \"fdenytsconnections\"=dword:00000000 >> c:\\reg.reg" fullword ascii
		$s2 = "echo [HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server] >" ascii
		$s3 = "echo \"Tsenabled\"=dword:00000001 >> c:\\reg.reg" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <20KB and all of them
}
