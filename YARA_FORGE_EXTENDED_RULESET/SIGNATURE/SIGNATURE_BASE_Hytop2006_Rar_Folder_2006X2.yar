rule SIGNATURE_BASE_Hytop2006_Rar_Folder_2006X2
{
	meta:
		description = "Webshells Auto-generated - file 2006X2.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "bda89055-27f5-50b7-86a3-2c75a5f3eadc"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L7753-L7765"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "cc5bf9fc56d404ebbc492855393d7620"
		logic_hash = "0df587ccaf41d11c6be90ef631ce8b21f95f08fa8f71e62463c378455b312f4a"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s2 = "Powered By "
		$s3 = " \" onClick=\"this.form.sharp.name=this.form.password.value;this.form.action=this."

	condition:
		all of them
}
