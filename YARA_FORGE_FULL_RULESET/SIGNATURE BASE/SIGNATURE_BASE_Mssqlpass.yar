rule SIGNATURE_BASE_Mssqlpass : FILE
{
	meta:
		description = "Chinese Hacktool Set - file MSSqlPass.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "d45b417f-3649-5603-bd19-8b8bcc19dabc"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_cn_hacktools.yar#L1106-L1121"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "172b4e31ed15d1275ac07f3acbf499daf9a055d7"
		logic_hash = "8037316eb157f8693bd342911af5fe5292f3ef8a3c169c80bc70edbabd7a92e6"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "Reveals the passwords stored in the Registry by Enterprise Manager of SQL Server" wide
		$s1 = "empv.exe" fullword wide
		$s2 = "Enterprise Manager PassView" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <120KB and all of them
}
