rule SIGNATURE_BASE_CN_Honker_Webshell_Su7_X_9_X : FILE
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file su7.x-9.x.asp"
		author = "Florian Roth (Nextron Systems)"
		id = "5d546ce8-6f8f-5b0b-9472-23f283ef9f80"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_webshells.yar#L548-L563"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "808396b51023cc8356f8049cfe279b349ca08f1a"
		logic_hash = "2d2398cf0f9e253eea343d39b6555f2633f92f627f1c93cc28123d5a7f3d1bf1"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "returns=httpopen(\"LoginID=\"&user&\"&FullName=&Password=\"&pass&\"&ComboPasswor" ascii
		$s1 = "returns=httpopen(\"\",\"POST\",\"http://127.0.0.1:\"&port&\"/Admin/XML/User.xml?" ascii

	condition:
		filesize <59KB and all of them
}
